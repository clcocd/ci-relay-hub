import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import test from "node:test";

import worker from "../worker/index.mjs";

const repository = { id: 1432951415, full_name: "clcocd/GallFlowProject-Beta" };
const delivery = "12345678-1234-1234-1234-1234567890ab";
const webhookKey = "synthetic-webhook-key";
const dispatchKey = "synthetic-dispatch-key";
const sign = (key, body) => createHmac("sha256", key).update(body).digest("hex");

function request(event, payload, key = webhookKey, path = "/github") {
  const body = JSON.stringify(payload);
  return new Request("https://worker.test" + path, {
    method: "POST",
    headers: {
      "X-GitHub-Event": event,
      "X-GitHub-Delivery": delivery,
      "X-Hub-Signature-256": "sha256=" + sign(key, body),
    },
    body,
  });
}

test("valid PR and base events are queued, unrelated and forged events are rejected", async () => {
  const queued = [];
  const env = {
    WEBHOOK_SECRET: webhookKey,
    DCR_WEBHOOK_SECRET: "dcr-secret-fixture",
    SOURCES: JSON.stringify({ [repository.id]: { repository: repository.full_name, alias: "beta", branch: "main" } }),
    RELAY_QUEUE: { send: async (data) => queued.push(data) },
  };
  const pr = { repository, action: "synchronize", number: 17, pull_request: { base: { ref: "main" } } };
  const retarget = {
    ...pr, action: "edited", changes: { base: { ref: { from: "main" } } },
    pull_request: { base: { ref: "other" } },
  };
  assert.equal((await worker.fetch(request("pull_request", pr), env)).status, 202);
  assert.equal((await worker.fetch(request("pull_request", retarget), env)).status, 202);
  assert.equal((await worker.fetch(request("pull_request", pr, "forged-key"), env)).status, 401);
  assert.equal((await worker.fetch(request("push", { repository, ref: "refs/heads/other" }), env)).status, 204);
  assert.equal((await worker.fetch(request("push", { repository, ref: "refs/heads/main" }), env)).status, 202);
  assert.deepEqual(queued, [{ source: "beta", pr: 17, delivery }, { source: "beta", pr: 17, delivery }, { source: "beta", delivery }]);

  env.SOURCES = JSON.stringify({
    [repository.id]: { repository: repository.full_name, alias: "beta", branch: "main" },
    1464038807: { repository: "clcocd/DCR-Kotlin", alias: "dcr", branch: "main", path: "/github/dcr-kotlin" },
  });
  const dcrEvent = {
    repository: { id: 1464038807, full_name: "clcocd/DCR-Kotlin" },
    action: "opened", number: 27, pull_request: { base: { ref: "main" } },
  };
  assert.equal((await worker.fetch(request("pull_request", dcrEvent), env)).status, 403);
  assert.equal((await worker.fetch(request("pull_request", dcrEvent, "dcr-secret-fixture", "/github"), env)).status, 401);
  assert.equal((await worker.fetch(request("pull_request", dcrEvent, webhookKey, "/github/dcr-kotlin"), env)).status, 401);
  assert.equal((await worker.fetch(request("pull_request", dcrEvent, "dcr-secret-fixture", "/github/dcr-kotlin"), env)).status, 202);
  assert.deepEqual(queued.at(-1), { source: "dcr", pr: 27, delivery });

});

test("Worker verifies dispatch signatures without sharing its secret with GitHub Actions", async () => {
  const env = { RELAY_DISPATCH_SECRET: dispatchKey };
  const envelope = JSON.stringify({ source: "dcr", pr: 17, event: "ci-relay-dcr-pr" });
  const request = (signature) => new Request("https://worker.test/verify-dispatch", {
    method: "POST",
    body: JSON.stringify({ envelope, signature }),
  });
  assert.equal((await worker.fetch(request(sign(dispatchKey, envelope)), env)).status, 204);
  assert.equal((await worker.fetch(request(sign("wrong-secret", envelope)), env)).status, 403);
  assert.equal((await worker.fetch(request("invalid"), env)).status, 400);
});

test("queue posts a signed dispatch and retries a GitHub outage", async (t) => {
  const env = { RELAY_DISPATCH_SECRET: dispatchKey, GITHUB_DISPATCH_TOKEN: "fixture", RELAY_REPOSITORY: "clcocd/ci-relay-hub" };
  let calls = 0;
  t.mock.method(globalThis, "fetch", async (url, options) => {
    assert.equal(url, "https://api.github.com/repos/clcocd/ci-relay-hub/dispatches");
    const dispatch = JSON.parse(options.body);
    const { signature, envelope, key } = dispatch.client_payload;
    assert.equal(dispatch.event_type, "ci-relay-pr");
    assert.equal(key, "beta-17");
    assert.equal(sign(dispatchKey, envelope), signature);
    assert.equal(JSON.parse(envelope).pr, 17);
    return new Response(null, { status: ++calls === 1 ? 503 : 204 });
  });
  const outcomes = [];
  const message = {
    body: { source: "beta", pr: 17, delivery }, attempts: 1,
    ack: () => outcomes.push("ack"), retry: () => outcomes.push("retry"),
  };
  await worker.queue({ messages: [message, message] }, env);
  assert.deepEqual(outcomes, ["retry", "ack"]);
});

test("DCR queue events use the dedicated repository_dispatch names", async (t) => {
  const env = { RELAY_DISPATCH_SECRET: dispatchKey, GITHUB_DISPATCH_TOKEN: "fixture", RELAY_REPOSITORY: "clcocd/ci-relay-hub" };
  const seen = [];
  t.mock.method(globalThis, "fetch", async (url, options) => {
    assert.equal(url, "https://api.github.com/repos/clcocd/ci-relay-hub/dispatches");
    seen.push(JSON.parse(options.body).event_type);
    return new Response(null, { status: 204 });
  });
  const make = (body) => ({ body, attempts: 1, ack: () => {}, retry: () => assert.fail("Unexpected retry") });
  await worker.queue({ messages: [
    make({ source: "dcr", pr: 27, delivery }),
    make({ source: "dcr", delivery }),
  ] }, env);
  assert.deepEqual(seen, ["ci-relay-dcr-pr", "ci-relay-dcr-base"]);
});
