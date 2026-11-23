const encoder = new TextEncoder();
const PR_ACTIONS = new Set([
  "opened", "synchronize", "reopened", "edited", "ready_for_review",
  "converted_to_draft", "closed",
]);
const MAX_BODY = 2 * 1024 * 1024;

async function hmacKey(secret) {
  return crypto.subtle.importKey(
    "raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" },
    false, ["sign", "verify"],
  );
}

function hex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function validSignature(secret, signature, body) {
  if (!secret || !/^sha256=[a-f0-9]{64}$/.test(signature ?? "")) return false;
  const expected = Uint8Array.from(signature.slice(7).match(/../g), (pair) => parseInt(pair, 16));
  return crypto.subtle.verify("HMAC", await hmacKey(secret), expected, body);
}

async function readBody(request) {
  const reader = request.body?.getReader();
  const chunks = [];
  let size = 0;
  if (!reader) return new Uint8Array();
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > MAX_BODY) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.length;
  }
  return body;
}

async function receive(request, env) {
  const path = new URL(request.url).pathname;
  const secret = path === "/github" ? env.WEBHOOK_SECRET
    : path === "/github/dcr-kotlin" ? env.DCR_WEBHOOK_SECRET : null;
  if (request.method !== "POST" || !["/github", "/github/dcr-kotlin"].includes(path)) {
    return new Response(null, { status: 404 });
  }
  const body = await readBody(request);
  if (!body) return new Response(null, { status: 413 });
  const signature = request.headers.get("X-Hub-Signature-256");
  if (!await validSignature(secret, signature, body)) {
    return new Response(null, { status: 401 });
  }

  const event = request.headers.get("X-GitHub-Event");
  if (event === "ping") return new Response(null, { status: 204 });
  let payload;
  try {
    payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
  } catch {
    return new Response(null, { status: 400 });
  }
  if (!payload || typeof payload !== "object") return new Response(null, { status: 400 });
  const source = JSON.parse(env.SOURCES)[String(payload.repository?.id)];
  if (!source || payload.repository?.full_name !== source.repository
      || path !== (source.path ?? "/github")) {
    return new Response(null, { status: 403 });
  }
  const delivery = request.headers.get("X-GitHub-Delivery");
  if (!/^[a-f0-9-]{36}$/.test(delivery ?? "")) return new Response(null, { status: 400 });

  let requestData;
  if (event === "pull_request" && PR_ACTIONS.has(payload.action)) {
    if (!Number.isSafeInteger(payload.number) || payload.number < 1) {
      return new Response(null, { status: 400 });
    }
    if (payload.action === "edited" && !payload.changes?.base) {
      return new Response(null, { status: 204 });
    }
    const target = payload.pull_request?.base?.ref;
    const previousTarget = payload.changes?.base?.ref?.from;
    if (target === source.branch || previousTarget === source.branch) {
      requestData = { source: source.alias, pr: payload.number, delivery };
    }
  } else if (event === "push" && payload.ref === "refs/heads/" + source.branch) {
    requestData = { source: source.alias, delivery };
  }
  if (!requestData) return new Response(null, { status: 204 });
  await env.RELAY_QUEUE.send(requestData);
  return new Response(null, { status: 202 });
}

async function verifyDispatch(request, env) {
  if (request.method !== "POST") return new Response(null, { status: 405 });
  const body = await readBody(request);
  if (!body) return new Response(null, { status: 413 });
  let payload;
  try {
    payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
  } catch {
    return new Response(null, { status: 400 });
  }
  if (typeof payload?.envelope !== "string" || payload.envelope.length > 1024
      || typeof payload.signature !== "string" || !/^[a-f0-9]{64}$/.test(payload.signature)) {
    return new Response(null, { status: 400 });
  }
  const valid = await validSignature(
    env.RELAY_DISPATCH_SECRET, "sha256=" + payload.signature, encoder.encode(payload.envelope),
  );
  return new Response(null, { status: valid ? 204 : 403, headers: { "Cache-Control": "no-store" } });
}

async function dispatch(data, env) {
  if (!env.RELAY_DISPATCH_SECRET || !env.GITHUB_DISPATCH_TOKEN ||
      !/^[a-zA-Z0-9_-]+\/[a-zA-Z0-9_.-]+$/.test(env.RELAY_REPOSITORY ?? "")) {
    throw new Error("Missing dispatch configuration");
  }
  const prefix = data.source === "beta" ? "ci-relay" : "ci-relay-" + data.source;
  const event_type = prefix + (data.pr ? "-pr" : "-base");
  const envelope = JSON.stringify({ ...data, event: event_type, issued: Math.floor(Date.now() / 1000) });
  const signature = hex(new Uint8Array(await crypto.subtle.sign(
    "HMAC", await hmacKey(env.RELAY_DISPATCH_SECRET), encoder.encode(envelope),
  )));
  const client_payload = { envelope, signature };
  if (data.pr) client_payload.key = data.source + "-" + data.pr;
  const response = await fetch(`https://api.github.com/repos/${env.RELAY_REPOSITORY}/dispatches`, {
    method: "POST",
    redirect: "manual",
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: "Bearer " + env.GITHUB_DISPATCH_TOKEN,
      "Content-Type": "application/json",
      "User-Agent": "ci-relay-worker",
      "X-GitHub-Api-Version": "2022-11-28",
    },
    body: JSON.stringify({ event_type, client_payload }),
  });
  if (response.status !== 204) {
    await response.body?.cancel();
    throw new Error("GitHub dispatch HTTP " + response.status);
  }
  console.log("GitHub dispatch accepted", data.source, data.delivery);
}

export default {
  async fetch(request, env) {
    if (new URL(request.url).pathname === "/verify-dispatch") {
      try {
        return await verifyDispatch(request, env);
      } catch {
        return new Response(null, { status: 503 });
      }
    }
    try {
      return await receive(request, env);
    } catch {
      console.error("Webhook could not be queued");
      return new Response(null, { status: 503 });
    }
  },

  async queue(batch, env) {
    for (const message of batch.messages) {
      try {
        await dispatch(message.body, env);
        message.ack();
      } catch (error) {
        console.error("Dispatch failed", error.message);
        message.retry({ delaySeconds: Math.min(900, 15 * 2 ** message.attempts) });
      }
    }
  },
};
