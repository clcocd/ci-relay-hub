#!/usr/bin/env python3
"""Trusted control jobs. These jobs never check out or execute a source PR."""

import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# The relay core is shared; each source defines its own verification profile.
SOURCES = {
    "beta": {
        "repository": "clcocd/GallFlowProject-Beta",
        "branch": "main",
        "read_token": "BETA_CI_TOKEN",
        "status_token": "BETA_CI_TOKEN",
        "control_token": "BETA_CONTROL_TOKEN",
        "contexts": ("ci-relay/macOS", "ci-relay/Windows"),
        "runners": (
            {"runner": "macos-15", "profile": "beta", "context": "ci-relay/macOS"},
            {"runner": "windows-latest", "profile": "beta", "context": "ci-relay/Windows"},
        ),
    },
    "dcr": {
        "repository": "clcocd/DCR-Kotlin",
        "branch": "main",
        "read_token": "DCR_CI_TOKEN",
        "status_token": "DCR_CI_TOKEN",
        "control_token": "DCR_CI_TOKEN",
        "contexts": ("ci-relay/Linux",),
        "runners": (
            {"runner": "ubuntu-latest", "profile": "dcr", "context": "ci-relay/Linux"},
        ),
    },
}
CONTEXTS = SOURCES["beta"]["contexts"]  # Legacy Beta test fixture.

SHA = re.compile(r"[0-9a-f]{40}")
GUID = re.compile(r"[0-9a-f-]{36}")
PENDING_TTL = dt.timedelta(hours=2)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def request(path, token, *, method="GET", payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {os.environ[token]}",
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    req = urllib.request.Request("https://api.github.com" + path, data, headers, method=method)
    with urllib.request.build_opener(NoRedirect()).open(req, timeout=25) as response:
        return json.load(response) if response.status != 204 else None


def source_api(source, path, *, token="read", **kwargs):
    # Use only the token allocated to this private source.
    role = {"read": "read_token", "status": "status_token", "control": "control_token"}
    secret_name = source[role[token]]
    if not os.environ.get(secret_name):
        raise RuntimeError(f"Missing token secret: {secret_name}")
    return request(f"/repos/{source['repository']}{path}", secret_name, **kwargs)


def emit(name, value):
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
        output.write(f"{name}={value}\n")


def dispatch_signature(envelope):
    secret = os.environ["RELAY_DISPATCH_SECRET"]
    if len(secret) < 32:
        raise ValueError("Dispatch key is missing or too short")
    return hmac.new(secret.encode(), envelope.encode(), hashlib.sha256).hexdigest()


def authenticate(event):
    payload = event.get("client_payload") or {}
    envelope, signature = payload.get("envelope"), payload.get("signature")
    if not isinstance(envelope, str) or len(envelope) > 1024:
        raise ValueError("Invalid dispatch envelope")
    if not isinstance(signature, str) or not re.fullmatch("[0-9a-f]{64}", signature):
        raise ValueError("Invalid dispatch signature")
    if not hmac.compare_digest(dispatch_signature(envelope), signature):
        raise ValueError("Invalid dispatch signature")
    data = json.loads(envelope)
    if not isinstance(data, dict):
        raise ValueError("Invalid dispatch data")
    alias = data.get("source")
    if alias not in SOURCES or not GUID.fullmatch(data.get("delivery", "")):
        raise ValueError("Invalid dispatch source or delivery")
    prefix = "ci-relay" if alias == "beta" else f"ci-relay-{alias}"
    kind = "pr" if "pr" in data else "base"
    if data.get("event") != event.get("action") or data.get("event") != f"{prefix}-{kind}":
        raise ValueError("Invalid dispatch event")
    now = time.time()
    issued = data.get("issued")
    if type(issued) is not int or not now - 7200 <= issued <= now + 60:
        raise ValueError("Expired dispatch")
    if kind == "pr":
        number = data.get("pr")
        if type(number) is not int or not 1 <= number <= 2**53 - 1:
            raise ValueError("Invalid PR number")
    key = f"{data['source']}-{data['pr']}" if "pr" in data else None
    if payload.get("key") != key:
        raise ValueError("Invalid dispatch concurrency key")
    return data


def event_data():
    return authenticate(json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text()))


def require_enrolled(alias):
    enabled = {part.strip() for part in (os.environ.get("CI_RELAY_PUBLIC_SOURCE") or "dcr").split(",") if part.strip()}
    if alias not in enabled:
        raise RuntimeError("CI relay is disabled for this source")
    return SOURCES[alias]


def send_pr(alias, number, delivery):
    prefix = "ci-relay" if alias == "beta" else f"ci-relay-{alias}"
    event_type = f"{prefix}-pr"
    envelope = json.dumps({
        "source": alias, "pr": number, "delivery": delivery,
        "event": event_type, "issued": int(time.time()),
    }, separators=(",", ":"))
    request(f"/repos/{os.environ['GITHUB_REPOSITORY']}/dispatches", "RELAY_TOKEN", method="POST", payload={
        "event_type": event_type,
        "client_payload": {
            "key": f"{alias}-{number}", "envelope": envelope,
            "signature": dispatch_signature(envelope),
        },
    })


def route():
    data = event_data()
    source = require_enrolled(data["source"])
    branch = urllib.parse.quote(source["branch"], safe="")
    for page in range(1, 101):
        prs = source_api(source, f"/pulls?state=open&base={branch}&per_page=100&page={page}")
        for pr in prs:
            send_pr(data["source"], pr["number"], data["delivery"])
        if len(prs) < 100:
            return
    raise RuntimeError("Base update exceeded the open PR routing limit")


def protection_allows_relay(protection, source=None):
    checks = protection.get("required_status_checks") or {}
    review = protection.get("required_pull_request_reviews") or {}
    bypass = review.get("bypass_pull_request_allowances") or {}
    return (
        checks.get("strict") is True
        and set((source or SOURCES["beta"])["contexts"]).issubset(checks.get("contexts") or [])
        and protection.get("enforce_admins", {}).get("enabled") is True
        and protection.get("allow_force_pushes", {}).get("enabled") is False
        and protection.get("allow_deletions", {}).get("enabled") is False
        and not any(bypass.values())
    )


def require_protection(source):
    branch = urllib.parse.quote(source["branch"], safe="")
    protection = source_api(source, f"/branches/{branch}/protection")
    if not protection_allows_relay(protection, source):
        raise RuntimeError("Source requires strict relay checks, with no protection bypass")


def pull(source, number):
    return source_api(source, f"/pulls/{number}")


def base_sha(source):
    branch = urllib.parse.quote(source["branch"], safe="")
    return source_api(source, f"/git/ref/heads/{branch}")["object"]["sha"]


def eligible(source, pr):
    return (
        pr["state"] == "open" and not pr.get("draft")
        and pr["base"]["ref"] == source["branch"]
    )


def matching(source, number, item):
    pr = pull(source, number)
    return (
        eligible(source, pr) and pr["head"]["sha"] == item["head"]
        and base_sha(source) == item["base"]
    )


def current_snapshot(source, number):
    for delay in (0, 1, 2, 4, 8):
        time.sleep(delay)
        pr = pull(source, number)
        if not eligible(source, pr):
            return None
        item = {"head": pr["head"]["sha"], "base": base_sha(source)}
        if not all(SHA.fullmatch(value) for value in item.values()):
            raise ValueError("Invalid source SHA")
        if pr["base"]["sha"] != item["base"]:
            continue
        merge_sha = pr.get("merge_commit_sha")
        if pr.get("mergeable") is False:
            return {**item, "merge": None, "conflict": True}
        if pr.get("mergeable") is True and SHA.fullmatch(merge_sha or ""):
            return {**item, "merge": merge_sha, "conflict": False}
    return {**item, "merge": None, "conflict": False}


def description(item):
    return f"base:{item['base']} merge:{item['merge'] or 'unavailable'}"


def status(source, item, state, message, context=None):
    for check in (context,) if context else source["contexts"]:
        source_api(source, f"/statuses/{item['head']}", token="status",
                   method="POST", payload={
                       "state": state, "context": check,
                       "description": f"{description(item)} | {message}",
                   })


def already_verified(source, item):
    if os.environ["GITHUB_RUN_ATTEMPT"] != "1":
        return False
    combined = source_api(source, f"/commits/{item['head']}/status?per_page=100")
    latest = {entry["context"]: entry for entry in combined["statuses"]}
    for context in source["contexts"]:
        entry = latest.get(context)
        if not entry or not (entry.get("description") or "").startswith(description(item) + " | "):
            return False
        if entry["state"] == "pending":
            created = dt.datetime.fromisoformat(entry["created_at"].replace("Z", "+00:00"))
            if dt.datetime.now(dt.timezone.utc) - created >= PENDING_TTL:
                return False
        elif entry["state"] not in {"success", "failure"}:
            return False
    return True


# Only explicitly reviewed dependency updates may omit browser E2E.
# A missing/truncated patch or any unrelated edit falls back to full CI.
DCR_LIGHT_PACKAGES = {"lucide-react", "@types/bun", "@types/react", "@types/react-dom", "shadcn", "vite"}
DCR_TRANSITIVE_PACKAGES = {"shadcn", "vite"}


def dcr_lightweight_renovate(source, number, item):
    pr = pull(source, number)
    head = pr.get("head") or {}
    if (pr.get("user") or {}).get("login") != "renovate[bot]":
        return False
    if (pr.get("changed_files") not in (1, 2) or head.get("sha") != item["head"]
            or (head.get("repo") or {}).get("full_name") != source["repository"]
            or (pr.get("base") or {}).get("sha") != item["base"]):
        return False

    files = source_api(source, f"/pulls/{number}/files?per_page=100")
    if not isinstance(files, list) or len(files) != pr["changed_files"]:
        return False
    changes = {file.get("filename"): file for file in files}
    if any(file.get("status") != "modified" for file in files):
        return False

    def edited_lines(file):
        patch = file.get("patch")
        if not isinstance(patch, str):
            return None
        lines = patch.splitlines()
        removed = [line[1:].strip() for line in lines
                   if line.startswith("-") and not line.startswith("---")]
        added = [line[1:].strip() for line in lines
                 if line.startswith("+") and not line.startswith("+++")]
        return removed, added


    # Kotlin/JS compiler updates already receive Kotlin, JS, WXT and unit checks.
    if set(changes) == {"kotlin/build.gradle.kts"}:
        file = changes["kotlin/build.gradle.kts"]
        edits = edited_lines(file)
        if (file.get("additions") != 1 or file.get("deletions") != 1
                or not edits or len(edits[0]) != 1 or len(edits[1]) != 1):
            return False
        pattern = r'kotlin\("multiplatform"\)\s+version\s+"(\d+\.\d+\.\d+)"'
        old = re.fullmatch(pattern, edits[0][0])
        new = re.fullmatch(pattern, edits[1][0])
        if not old or not new:
            return False
        before = tuple(map(int, old.group(1).split(".")))
        after = tuple(map(int, new.group(1).split(".")))
        return after > before and after[0] == before[0]

    if set(changes) != {"package.json", "bun.lock"}:
        return False
    if (changes["package.json"].get("additions") != 1
            or changes["package.json"].get("deletions") != 1):
        return False

    manifest = edited_lines(changes["package.json"])
    lock = edited_lines(changes["bun.lock"])
    if not manifest or not lock or len(manifest[0]) != 1 or len(manifest[1]) != 1:
        return False
    if (len(lock[0]) != changes["bun.lock"].get("deletions")
            or len(lock[1]) != changes["bun.lock"].get("additions")):
        return False

    def dependency(line):
        match = re.fullmatch(r'"([^"]+)":\s*"(\^?\d+\.\d+\.\d+)",?', line)
        return match.groups() if match else None

    before = dependency(manifest[0][0])
    after = dependency(manifest[1][0])
    if not before or not after or before[0] != after[0] or before[0] not in DCR_LIGHT_PACKAGES:
        return False
    name, old = before
    new = after[1]
    if name in DCR_TRANSITIVE_PACKAGES:
        # Bun may also update resolved transitive package entries, but not other
        # workspace dependency ranges or arbitrary lockfile metadata.
        for lines, spec in ((lock[0], old), (lock[1], new)):
            workspace = f'"{name}": "{spec}",'
            if lines.count(workspace) != 1 or any(
                    line and line != workspace and not re.fullmatch(r'"[^"]+": \["[^"]+@[^"]+",.*\],?', line)
                    for line in lines):
                return False
    elif len(lock[0]) != 2 or len(lock[1]) != 2:
        return False
    if old.startswith("^") != new.startswith("^"):
        return False
    old_version = tuple(map(int, old.lstrip("^").split(".")))
    new_version = tuple(map(int, new.lstrip("^").split(".")))
    if (new_version <= old_version or new_version[0] != old_version[0]
            or (old_version[0] == 0 and new_version[1] != old_version[1])):
        return False

    def lock_matches(lines, spec):
        # Require both the workspace range and the resolved package to change.
        return (any(line.startswith(f'"{name}": "{spec}"') for line in lines)
                and any(line.startswith(f'"{name}": ["{name}@{spec.lstrip("^")}"')
                        for line in lines))

    return lock_matches(lock[0], old) and lock_matches(lock[1], new)


def prepare():
    data = event_data()
    source = require_enrolled(data["source"])
    if data["source"] == "beta":
        if source_api(source, "/actions/permissions")["enabled"] is not False:
            raise RuntimeError("Disable source repository Actions before cutover")
        require_protection(source)
    item = current_snapshot(source, data["pr"])
    if not item:
        return
    if not matching(source, data["pr"], item) or already_verified(source, item):
        return
    emit("candidate", json.dumps(item, separators=(",", ":")))
    if item["conflict"]:
        status(source, item, "failure", "merge conflict")
        return
    if not item["merge"]:
        status(source, item, "error", "merge snapshot unavailable")
        raise RuntimeError("GitHub did not compute a current merge snapshot")
    status(source, item, "pending", "verifying")
    light_dcr = data["source"] == "dcr" and dcr_lightweight_renovate(source, data["pr"], item)
    if light_dcr:
        print("Lightweight CI: verified low-risk Renovate dependency-only PR (E2E skipped).")
    runners = [
        {**runner, "repository": source["repository"], "checkout_secret": source["read_token"],
         "skip_e2e": light_dcr if runner["profile"] == "dcr" else False}
        for runner in source["runners"]
    ]
    emit("matrix", json.dumps({"include": runners}, separators=(",", ":")))
    emit("pr", data["pr"])


def merge_or_update(source, number, pr, item):
    if pr["user"]["login"] == "renovate[bot]":
        return
    require_protection(source)
    comparison = source_api(source, f"/compare/{item['base']}...{item['head']}")
    if comparison["behind_by"] > 0:
        if (pr["head"].get("repo") or {}).get("full_name") != source["repository"]:
            raise RuntimeError("GitHub requires the fork author to update this branch")
        source_api(source, f"/pulls/{number}/update-branch", token="control",
                   method="PUT", payload={"expected_head_sha": item["head"]})
        print("Requested an up-to-date PR branch; the new head will be tested by webhook.")
        return
    # GitHub enforces the head at merge time and strict protection enforces the base.
    if not matching(source, number, item):
        return
    response = source_api(source, f"/pulls/{number}/merge", token="control",
                          method="PUT", payload={"sha": item["head"], "merge_method": "merge"})
    if not response.get("merged"):
        raise RuntimeError("GitHub did not merge the PR")
    print("GitHub merged the tested PR head.")



def delete_dcr_merged_branch(source, pr, item):
    head = pr["head"]
    name = head.get("ref")
    if ((head.get("repo") or {}).get("full_name") != source["repository"]
            or not name or name == source["branch"]):
        return
    path = f"/git/ref/heads/{urllib.parse.quote(name, safe='/')}"
    try:
        current = source_api(source, path)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return
        raise
    if current["object"]["sha"] != item["head"]:
        print("Skipping PR branch deletion: branch head changed.")
        return
    source_api(source, f"/git/refs/heads/{urllib.parse.quote(name, safe='/')}",
               token="control", method="DELETE")
    print(f"Deleted merged DCR PR branch: {name}")


def merge_dcr_tested(source, number, item):
    # The tested merge commit must contain exactly the original base and head.
    # A non-forced ref update is rejected if main advanced in the meantime.
    if not matching(source, number, item):
        return
    pr = pull(source, number)
    if pr["user"]["login"] == "renovate[bot]":
        return
    if (not eligible(source, pr) or pr["head"]["sha"] != item["head"]
            or pr.get("merge_commit_sha") != item["merge"]):
        return
    commit = source_api(source, f"/git/commits/{item['merge']}")
    if [parent["sha"] for parent in commit["parents"]] != [item["base"], item["head"]]:
        raise RuntimeError("Tested DCR merge commit parents changed")
    if not matching(source, number, item):
        return
    result = source_api(source, f"/git/refs/heads/{source['branch']}",
                        token="control", method="PATCH",
                        payload={"sha": item["merge"], "force": False})
    if result.get("object", {}).get("sha") != item["merge"]:
        raise RuntimeError("GitHub did not advance main to the tested merge commit")
    print("Advanced DCR main to the exact tested merge commit without force.")
    delete_dcr_merged_branch(source, pr, item)


def finish():
    data = event_data()
    source = require_enrolled(data["source"])
    item = json.loads(os.environ["CANDIDATE"])
    if not item["merge"] or not matching(source, data["pr"], item):
        return
    if os.environ["PREPARE_RESULT"] != "success":
        status(source, item, "error", "snapshot setup failed")
        return
    outcome = os.environ["BUILD_RESULT"]
    state = {"success": "success", "failure": "failure"}.get(outcome, "error")
    if state == "success":
        if data["source"] == "beta":
            try:
                require_protection(source)
            except (RuntimeError, urllib.error.HTTPError):
                status(source, item, "error", "required branch protection unavailable")
                raise
        fresh = current_snapshot(source, data["pr"])
        if fresh != item or not matching(source, data["pr"], item):
            return
    status(source, item, state, "build " + outcome)
    if state == "success" and matching(source, data["pr"], item):
        try:
            if data["source"] == "dcr":
                merge_dcr_tested(source, data["pr"], item)
            else:
                merge_or_update(source, data["pr"], pull(source, data["pr"]), item)
        except (RuntimeError, urllib.error.HTTPError):
            if matching(source, data["pr"], item):
                status(source, item, "error", "merge or branch update blocked")
            raise



def release_version(source, sha):
    if not SHA.fullmatch(sha):
        raise ValueError("Invalid release commit SHA")
    response = source_api(source, f"/contents/package.json?ref={sha}")
    content = base64.b64decode(response["content"]).decode("utf-8")
    version = json.loads(content)["version"]
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){2,3}", version):
        raise ValueError("Unsupported DCR release version")
    return version


def release_missing(source, tag):
    # Releases and tags are both checked to avoid overwriting existing artifacts.
    for path in (f"/releases/tags/{tag}", f"/git/ref/tags/{tag}"):
        try:
            source_api(source, path)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                continue
            raise
        return False
    return True


def release_gate():
    data = event_data()
    if data["source"] != "dcr":
        return
    source = require_enrolled(data["source"])
    sha = base_sha(source)
    version = release_version(source, sha)
    tag = f"v{version}-kotlin-test"
    if not release_missing(source, tag):
        print(f"Release already exists: {tag}")
        return
    emit("publish", "true")
    emit("source_sha", sha)
    emit("version", version)
    emit("tag", tag)


def release_verify():
    data = event_data()
    if data["source"] != "dcr":
        raise ValueError("Release event is not DCR-Kotlin")
    source = require_enrolled(data["source"])
    sha = os.environ["SOURCE_SHA"]
    version = os.environ["RELEASE_VERSION"]
    tag = os.environ["RELEASE_TAG"]
    if not SHA.fullmatch(sha) or base_sha(source) != sha:
        raise RuntimeError("DCR-Kotlin main changed during the release build")
    if release_version(source, sha) != version or tag != f"v{version}-kotlin-test":
        raise ValueError("Release metadata does not match the tested source")
    if not release_missing(source, tag):
        raise RuntimeError("Release tag already exists")
    print(f"Approved release {tag} from {sha}")


if __name__ == "__main__":
    commands = {"route": route, "prepare": prepare, "finish": finish,
                "release-gate": release_gate,
                "release-verify": release_verify}
    try:
        commands[sys.argv[1]]()
    except urllib.error.HTTPError as exc:
        print(f"::error::Trusted GitHub API request failed (HTTP {exc.code})", file=sys.stderr)
        sys.exit(1)
    except (KeyError, TypeError, ValueError, RuntimeError, urllib.error.URLError) as exc:
        message = str(exc) if type(exc) is RuntimeError else type(exc).__name__
        print(f"::error::Relay failed: {message}", file=sys.stderr)
        sys.exit(1)
