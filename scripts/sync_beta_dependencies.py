#!/usr/bin/env python3
"""Promote only verified Renovate dependency versions from Beta to stable.

Runs on the trusted public relay, never checks out or executes a private PR.
Writes only explicitly allowed version lines to the private stable repository.
"""

import base64
import re
import sys
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scripts import beta_legacy_relay as beta

BETA = "clcocd/GallFlowProject-Beta"
STABLE = "clcocd/GallFlowProject"
BRANCH = "main"
SYNC_TOKEN = "RELEASE_SYNC_TOKEN"
ALLOWED = {
    "build.gradle.kts",
    "composeApp/build.gradle.kts",
    "gradle/wrapper/gradle-wrapper.properties",
}
CONTEXTS = ("ci-relay/macOS", "ci-relay/Windows")
SHA = re.compile(r"[0-9a-f]{40}")


def api(repository, path, *, token, method="GET", payload=None):
    return beta.api(f"/repos/{repository}{path}", token_env=token,
                    method=method, payload=payload)


def checked_merge(pr):
    """Require two successful CI checks for the same tested merge snapshot."""
    head = pr["head"]["sha"]
    statuses = api(BETA, f"/commits/{head}/statuses?per_page=100",
                   token="BETA_CI_TOKEN")
    latest = {}
    for entry in statuses:  # GitHub returns the latest status first.
        latest.setdefault(entry["context"], entry)
    snapshots = []
    for context in CONTEXTS:
        item = latest.get(context)
        if not item or item["state"] != "success":
            return False
        description = item.get("description") or ""
        legacy = re.fullmatch(r"merge:([0-9a-f]{12}) \| PR #(\d+) \| success",
                              description)
        modern = re.fullmatch(
            r"base:([0-9a-f]{40}) merge:([0-9a-f]{40}) \| build success",
            description)
        if legacy and int(legacy.group(2)) == pr["number"]:
            snapshots.append(("legacy", legacy.group(1)))
        elif modern:
            snapshots.append(("modern", modern.group(1), modern.group(2)))
        else:
            return False
    return snapshots[0] == snapshots[1]


def version_signature(path, line):
    """Identify exactly one declarative version, preserving surrounding text."""
    if path == "gradle/wrapper/gradle-wrapper.properties":
        match = re.fullmatch(
            r"(distributionUrl=https\\://services\.gradle\.org/distributions/gradle-)"
            r"([0-9][A-Za-z0-9.+-]*)"
            r"(-(?:bin|all)\.zip)", line)
    elif path in ("build.gradle.kts", "composeApp/build.gradle.kts"):
        match = re.fullmatch(
            r'(\s*(?:kotlin\("[A-Za-z0-9_.-]+"\)|id\("[A-Za-z0-9_.-]+"\)) version ")'
            r'([A-Za-z0-9.+-]+)'
            r'("(?: apply false)?\s*)', line)
        if not match and path == "composeApp/build.gradle.kts":
            match = re.fullmatch(
                r'(\s*implementation\("[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+:)'
                r'([A-Za-z0-9.+-]+)'
                r'("\)\s*(?://[^\n]*)?)', line)
    else:
        return None
    if not match:
        return None
    prefix, version, suffix = match.groups()
    if "dev.kotlininside:kotlininside:" in prefix:
        return None  # Project-maintained KotlinInside is never auto-updated.
    return prefix, version, suffix


def changes_from_patch(path, patch):
    if not isinstance(patch, str) or not patch:
        raise ValueError(f"Missing complete dependency patch: {path}")
    removed = [line[1:] for line in patch.splitlines()
               if line.startswith("-") and not line.startswith("---")]
    added = [line[1:] for line in patch.splitlines()
             if line.startswith("+") and not line.startswith("+++")]
    if len(removed) != len(added) or not removed:
        raise ValueError(f"Not a pure version update: {path}")
    changes = []
    for before, after in zip(removed, added):
        a = version_signature(path, before)
        b = version_signature(path, after)
        if not a or not b or a[0] != b[0] or a[2] != b[2] or a[1] == b[1]:
            raise ValueError(f"Unexpected code change in dependency file: {path}")
        changes.append((before, after))
    return changes


def dependency_edits(pr_number):
    entries = api(BETA, f"/pulls/{pr_number}/files?per_page=100",
                  token="BETA_CI_TOKEN")
    if len(entries) >= 100:
        raise ValueError("PR has too many changed files to verify safely")
    edits = {}
    for entry in entries:
        path = entry["filename"]
        if path == "gradle/wrapper/gradle-wrapper.jar":
            raise ValueError("Binary Gradle wrapper changes require separate handling")
        if path not in ALLOWED:
            continue  # Beta-specific CI workflows and source must not be copied.
        if entry.get("status") != "modified":
            raise ValueError(f"Unexpected dependency file operation: {path}")
        edits[path] = changes_from_patch(path, entry.get("patch"))
    return edits


def apply_edits(content, path, changes):
    lines = content.splitlines(keepends=True)
    for before, after in changes:
        old = [i for i, line in enumerate(lines) if line.rstrip("\r\n") == before]
        new = [i for i, line in enumerate(lines) if line.rstrip("\r\n") == after]
        if len(new) == 1 and not old:
            continue  # The exact version was already promoted.
        if len(old) != 1 or new:
            raise ValueError(f"Stable version diverged; refusing overwrite: {path}")
        index = old[0]
        ending = "\r\n" if lines[index].endswith("\r\n") else (
            "\n" if lines[index].endswith("\n") else "")
        lines[index] = after + ending
    return "".join(lines)


def promote(pr_number, edits):
    """Create one atomic commit; a moving stable branch cannot be overwritten."""
    reference = api(STABLE, f"/git/ref/heads/{BRANCH}", token=SYNC_TOKEN)
    original = reference["object"]["sha"]
    commit = api(STABLE, f"/git/commits/{original}", token=SYNC_TOKEN)
    updated = {}
    for path, changes in edits.items():
        source = api(STABLE, f"/contents/{path}?ref={original}", token=SYNC_TOKEN)
        if source["encoding"] != "base64":
            raise ValueError(f"Unsupported stable file encoding: {path}")
        original_text = base64.b64decode(source["content"]).decode("utf-8")
        next_text = apply_edits(original_text, path, changes)
        if next_text != original_text:
            updated[path] = next_text
    if not updated:
        print(f"Beta PR #{pr_number}: dependency versions already synchronized.")
        return

    tree = []
    for path, content in updated.items():
        blob = api(STABLE, "/git/blobs", token=SYNC_TOKEN, method="POST",
                   payload={"content": base64.b64encode(content.encode()).decode(),
                            "encoding": "base64"})
        tree.append({"path": path, "mode": "100644", "type": "blob",
                     "sha": blob["sha"]})
    new_tree = api(STABLE, "/git/trees", token=SYNC_TOKEN, method="POST",
                   payload={"base_tree": commit["tree"]["sha"], "tree": tree})
    new_commit = api(STABLE, "/git/commits", token=SYNC_TOKEN, method="POST",
                     payload={"message": f"의존성: 베타 Renovate PR #{pr_number} 검증 변경 자동 반영",
                              "tree": new_tree["sha"], "parents": [original]})
    api(STABLE, f"/git/refs/heads/{BRANCH}", token=SYNC_TOKEN, method="PATCH",
        payload={"sha": new_commit["sha"], "force": False})
    print(f"Promoted Beta PR #{pr_number} to stable: {new_commit['sha']}. "
          f"Files: {', '.join(updated)}")


def main():
    # Reuse the existing HMAC-authenticated dispatch parser, never trust bare PR IDs.
    number = beta.webhook_pr_number()
    if number is None:
        return
    pr = api(BETA, f"/pulls/{number}", token="BETA_CI_TOKEN")
    if (pr.get("state") != "closed" or not pr.get("merged_at")
            or pr.get("user", {}).get("login") != "renovate[bot]"
            or pr.get("base", {}).get("ref") != BRANCH
            or (pr.get("head", {}).get("repo") or {}).get("full_name") != BETA):
        print(f"Beta PR #{number}: not a merged Renovate PR.")
        return
    merge_sha = pr.get("merge_commit_sha") or ""
    if not SHA.fullmatch(merge_sha) or not SHA.fullmatch(pr["head"]["sha"]):
        raise ValueError("Invalid merged PR SHA")
    ancestry = api(BETA, f"/compare/{merge_sha}...{BRANCH}",
                   token="BETA_CI_TOKEN")
    if ancestry.get("status") not in ("ahead", "identical"):
        print(f"Beta PR #{number}: merge no longer present in Beta main.")
        return
    if not checked_merge(pr):
        print(f"Beta PR #{number}: both CI checks did not pass for the same snapshot.")
        return
    edits = dependency_edits(number)
    if not edits:
        print(f"Beta PR #{number}: no stable dependency versions to copy.")
        return
    promote(number, edits)


if __name__ == "__main__":
    try:
        main()
    except (urllib.error.HTTPError, urllib.error.URLError, KeyError,
            TypeError, ValueError, RuntimeError) as exc:
        print(f"::error::Beta dependency sync failed: {exc}", file=sys.stderr)
        sys.exit(1)
