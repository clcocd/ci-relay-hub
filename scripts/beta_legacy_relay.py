#!/usr/bin/env python3
"""Discover Beta PR builds and report commit statuses to the private Beta repo.

No repository source is committed or uploaded by this tool.
"""

import datetime as dt
import hashlib
import hmac
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.error
import urllib.request
from pathlib import Path

REPO = "clcocd/GallFlowProject-Beta"
API = "https://api.github.com"
PLATFORMS = {"macOS": "macos-15", "Windows": "windows-latest"}
PENDING_TTL = dt.timedelta(hours=2)


def api(path: str, *, method: str = "GET", payload=None, token_env="BETA_CI_TOKEN"):
    token = os.environ.get(token_env, "").strip()
    if not token:
        raise RuntimeError(f"{token_env} secret is not configured")
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(API + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return None if response.status == 204 else json.load(response)
    except urllib.error.HTTPError as exc:
        # A merged PR may already have had its branch deleted; that 404 is expected.
        if exc.code != 404:
            body = exc.read(2048).decode("utf-8", errors="replace")
            try:
                message = json.loads(body).get("message", "")
            except (ValueError, AttributeError):
                message = "GitHub returned a non-JSON error"
            print(f"::error::GitHub API {method} {path} HTTP {exc.code}: {message}", file=sys.stderr)
        raise


def write_outputs(matrix):
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as out:
        out.write("has_work=" + ("true" if matrix else "false") + "\n")
        out.write("matrix=" + json.dumps({"include": matrix}, separators=(",", ":")) + "\n")


def checked(status, merge_sha, force):
    if force or not status:
        return False
    if f"merge:{merge_sha[:12]}" not in (status.get("description") or ""):
        return False
    if status.get("state") != "pending":
        return True
    created = dt.datetime.fromisoformat(status["created_at"].replace("Z", "+00:00"))
    return dt.datetime.now(dt.timezone.utc) - created < PENDING_TTL


def webhook_pr_number():
    if os.environ.get("GITHUB_EVENT_NAME") != "repository_dispatch":
        return None
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    payload = event.get("client_payload") or {}
    envelope, signature = payload.get("envelope"), payload.get("signature")
    secret = os.environ.get("RELAY_DISPATCH_SECRET", "")
    if len(secret) < 32 or not isinstance(envelope, str) or len(envelope) > 1024:
        raise ValueError("Invalid webhook dispatch envelope")
    expected = hmac.new(secret.encode(), envelope.encode(), hashlib.sha256).hexdigest()
    if not isinstance(signature, str) or not re.fullmatch("[a-f0-9]{64}", signature):
        raise ValueError("Invalid webhook dispatch signature")
    if not hmac.compare_digest(expected, signature):
        raise ValueError("Invalid webhook dispatch signature")
    data = json.loads(envelope)
    if data.get("source") != "beta" or data.get("event") != event.get("action"):
        raise ValueError("Invalid webhook dispatch target")
    issued = data.get("issued")
    now = time.time()
    if type(issued) is not int or not now - 7200 <= issued <= now + 60:
        raise ValueError("Expired webhook dispatch")
    if data["event"] == "ci-relay-base" and "pr" not in data and payload.get("key") is None:
        return None
    number = data.get("pr")
    if data["event"] != "ci-relay-pr" or type(number) is not int or not 1 <= number <= 2**53 - 1:
        raise ValueError("Invalid webhook PR number")
    if payload.get("key") != f"beta-{number}":
        raise ValueError("Invalid webhook concurrency key")
    return number


def get_pull(number):
    # GitHub calculates the PR merge ref asynchronously after a webhook.
    for delay in (0, 1, 2, 4, 8):
        time.sleep(delay)
        pr = api(f"/repos/{REPO}/pulls/{number}")
        if pr["state"] != "open" or pr.get("draft") or pr.get("mergeable") is not None:
            return pr
    return pr


def pull_pages(number):
    if number is not None:
        yield [get_pull(number)]
        return
    for page in range(1, 101):
        prs = api(f"/repos/{REPO}/pulls?state=open&base=main&per_page=100&page={page}")
        yield [get_pull(pr["number"]) for pr in prs]
        if len(prs) < 100:
            return
    raise RuntimeError("Exceeded the Beta PR page limit")


def discover():
    if not os.environ.get("BETA_CI_TOKEN"):
        print("::notice::BETA_CI_TOKEN secret missing; discovery skipped.")
        write_outputs([])
        return
    force = os.environ.get("FORCE", "false").lower() == "true"
    matrix = []
    number = webhook_pr_number()
    for prs in pull_pages(number):
        for pr in prs:
            if pr["state"] != "open" or pr.get("draft") or pr["base"]["ref"] != "main":
                continue
            if os.environ.get("GITHUB_EVENT_NAME") != "repository_dispatch" and pr["user"]["login"] != "renovate[bot]":
                continue
            head = pr["head"]
            if not head.get("repo") or head["repo"]["full_name"] != REPO:
                continue
            number = int(pr["number"])
            sha = head["sha"]
            merge_sha = pr.get("merge_commit_sha")
            if not re.fullmatch(r"[0-9a-f]{40}", sha):
                continue
            if pr.get("mergeable") is not True or not merge_sha or not re.fullmatch(r"[0-9a-f]{40}", merge_sha):
                print(f"PR #{number}: current merge commit not available.")
                continue

            statuses = api(f"/repos/{REPO}/commits/{sha}/statuses?per_page=100")
            latest = {}
            for item in statuses:  # newest first
                latest.setdefault(item["context"], item)
            for platform, runner in PLATFORMS.items():
                context = f"ci-relay/{platform}"
                if checked(latest.get(context), merge_sha, force):
                    continue
                matrix.append({
                    "pr": number,
                    "sha": sha,
                    "merge_sha": merge_sha,
                    "platform": platform,
                    "runner": runner,
                    "context": context,
                })
    print(f"Scheduled {len(matrix)} OS test jobs for eligible Beta PRs.")
    write_outputs(matrix)


def report():
    sha = os.environ["PR_SHA"]
    merge_sha = os.environ["MERGE_SHA"]
    context = os.environ["STATUS_CONTEXT"]
    pr = int(os.environ["PR_NUMBER"])
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or not re.fullmatch(r"[0-9a-f]{40}", merge_sha):
        raise ValueError("invalid commit SHA")
    if context not in ("ci-relay/macOS", "ci-relay/Windows"):
        raise ValueError("invalid status context")
    phase = os.environ["PHASE"]
    result = os.environ.get("JOB_RESULT", "")
    if phase == "start":
        state = "pending"
        message = "running"
    elif phase == "finish":
        state = {"success": "success", "failure": "failure"}.get(result, "error")
        message = result if result else "error"
    else:
        raise ValueError("invalid status phase")
    current = get_pull(pr)
    if (current["state"] != "open" or current.get("draft") or current["base"]["ref"] != "main"
            or current["head"]["sha"] != sha or current.get("merge_commit_sha") != merge_sha
            or current.get("mergeable") is not True):
        print(f"PR #{pr}: skipped {phase} status for a stale merge snapshot.")
        if phase == "start":
            raise RuntimeError("PR changed before build")
        return
    run_id = os.environ["GITHUB_RUN_ID"]
    payload = {
        "state": state,
        "context": context,
        "description": f"merge:{merge_sha[:12]} | PR #{pr} | {message}",
        "target_url": f"https://github.com/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{run_id}",
    }
    api(f"/repos/{REPO}/statuses/{sha}", method="POST", payload=payload)
    print(f"PR #{pr} {context}: {state}")



def delete_merged_pr_branch(pr):
    """Delete only unchanged, unshared head branches of merged Beta PRs."""
    if pr.get("state") != "closed" or not pr.get("merged_at"):
        return
    if (pr.get("base") or {}).get("ref") != "main":
        return
    head = pr.get("head") or {}
    name = head.get("ref")
    if ((head.get("repo") or {}).get("full_name") != REPO
            or not isinstance(name, str) or not name or name == "main"
            or not re.fullmatch(r"[A-Za-z0-9._/-]+", name)):
        return
    sha = head.get("sha")
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
        return

    ref = urllib.parse.quote(name, safe="/")
    try:
        current = api(f"/repos/{REPO}/git/ref/heads/{ref}", token_env="BETA_CI_TOKEN")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return
        raise
    if current["object"]["sha"] != sha:
        print(f"Preserving {name}: branch head changed since PR merge.")
        return

    head_filter = urllib.parse.quote(f"clcocd:{name}", safe="")
    open_prs = api(f"/repos/{REPO}/pulls?state=open&head={head_filter}&per_page=100",
                   token_env="BETA_CI_TOKEN")
    if open_prs:
        print(f"Preserving {name}: an open PR still uses this branch.")
        return

    api(f"/repos/{REPO}/git/refs/heads/{ref}", method="DELETE",
        token_env="BETA_CI_TOKEN")
    print(f"Deleted merged Beta PR branch: {name}")


def cleanup():
    """Prune merged branches on authenticated PR dispatch or sweep after deployment."""
    if os.environ.get("GITHUB_EVENT_NAME") == "push":
        for page in range(1, 11):
            prs = api(f"/repos/{REPO}/pulls?state=closed&base=main&per_page=100&page={page}",
                      token_env="BETA_CI_TOKEN")
            for pr in prs:
                delete_merged_pr_branch(pr)
            if len(prs) < 100:
                return
        raise RuntimeError("Exceeded merged Beta PR cleanup page limit")

    number = webhook_pr_number()
    if number is not None:
        pr = api(f"/repos/{REPO}/pulls/{number}", token_env="BETA_CI_TOKEN")
        delete_merged_pr_branch(pr)


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["discover"]:
            discover()
        elif sys.argv[1:] == ["report"]:
            report()
        elif sys.argv[1:] == ["cleanup"]:
            cleanup()
        else:
            raise ValueError("usage: beta_legacy_relay.py discover|report|cleanup")
    except (urllib.error.HTTPError, urllib.error.URLError, KeyError, ValueError, RuntimeError) as exc:
        print(f"::error::CI relay failed: {exc}", file=sys.stderr)
        sys.exit(1)
