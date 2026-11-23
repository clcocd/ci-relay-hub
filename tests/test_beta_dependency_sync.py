"""Security and behavior checks for Beta -> stable dependency promotion."""

import base64
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import sync_beta_dependencies as sync


class SyncTests(unittest.TestCase):
    def test_plugin_and_library_versions_only(self):
        examples = [
            ("build.gradle.kts", '    kotlin("jvm") version "2.4.21" apply false',
             '    kotlin("jvm") version "2.5.0" apply false'),
            ("build.gradle.kts", '    id("org.jetbrains.compose") version "1.12.2" apply false',
             '    id("org.jetbrains.compose") version "1.13.0" apply false'),
            ("composeApp/build.gradle.kts",
             '                implementation("org.jsoup:jsoup:1.24.1")',
             '                implementation("org.jsoup:jsoup:1.24.2")'),
            ("gradle/wrapper/gradle-wrapper.properties",
             r"distributionUrl=https\://services.gradle.org/distributions/gradle-9.9.2-bin.zip",
             r"distributionUrl=https\://services.gradle.org/distributions/gradle-9.10-bin.zip"),
        ]
        for path, old, new in examples:
            with self.subTest(path=path):
                edits = sync.changes_from_patch(
                    path, "@@ -1 +1 @@\n-" + old + "\n+" + new + "\n")
                self.assertEqual(edits, [(old, new)])
                self.assertEqual(sync.apply_edits(old + "\n", path, edits), new + "\n")

    def test_no_kotlininside_or_code_changes(self):
        for a, b in [
            ('implementation("dev.kotlininside:kotlininside:2.0.1")',
             'implementation("dev.kotlininside:kotlininside:2.1.0")'),
            ('version = "0.3.0"', 'version = "0.3.1"'),
            ('fun main() = unsafe()', 'fun main() = injected()'),
        ]:
            with self.subTest(old=a):
                with self.assertRaises(ValueError):
                    sync.changes_from_patch(
                        "composeApp/build.gradle.kts",
                        "@@ -1 +1 @@\n-" + a + "\n+" + b)

    def test_no_mixed_code_and_dependency_changes(self):
        patch_text = (
            "@@ -1,2 +1,2 @@\n"
            '-implementation("org.jsoup:jsoup:1.24.1")\n'
            '-version = "0.3.0"\n'
            '+implementation("org.jsoup:jsoup:1.24.2")\n'
            '+version = "0.3.1"\n'
        )
        with self.assertRaises(ValueError):
            sync.changes_from_patch("composeApp/build.gradle.kts", patch_text)

    def test_exact_old_version_required_but_repeated_events_are_noops(self):
        path = "composeApp/build.gradle.kts"
        before = '    implementation("org.jsoup:jsoup:1.24.1")'
        after = '    implementation("org.jsoup:jsoup:1.24.2")'
        self.assertEqual(sync.apply_edits(after + "\n", path, [(before, after)]),
                         after + "\n")
        with self.assertRaises(ValueError):
            sync.apply_edits('    implementation("org.jsoup:jsoup:1.23.0")\n',
                             path, [(before, after)])

    @patch("scripts.sync_beta_dependencies.api")
    def test_requires_both_matching_ci_successes(self, api):
        pr = {"number": 41, "head": {"sha": "a" * 40}}
        successful = lambda context, description: {
            "context": context, "state": "success", "description": description}
        valid = "merge:cccccccccccc | PR #41 | success"
        api.return_value = [successful("ci-relay/macOS", valid),
                            successful("ci-relay/Windows", valid)]
        self.assertTrue(sync.checked_merge(pr))
        api.return_value[1] = successful(
            "ci-relay/Windows", "merge:bbbbbbbbbbbb | PR #41 | success")
        self.assertFalse(sync.checked_merge(pr))
        api.return_value[1] = successful("ci-relay/Windows", valid)
        api.return_value[1]["state"] = "failure"
        self.assertFalse(sync.checked_merge(pr))
        modern = "base:" + "a" * 40 + " merge:" + "b" * 40 + " | build success"
        api.return_value = [successful("ci-relay/macOS", modern),
                            successful("ci-relay/Windows", modern)]
        self.assertTrue(sync.checked_merge(pr))

    @patch("scripts.sync_beta_dependencies.api")
    def test_dependency_edits_ignore_beta_ci_but_refuse_wrapper_binary(self, api):
        api.return_value = [
            {"filename": ".github/workflows/dependency-verification.yml",
             "status": "modified", "patch": "@@ -1 +1 @@\n-a\n+b"},
            {"filename": "composeApp/build.gradle.kts", "status": "modified",
             "patch": '@@ -1 +1 @@\n-implementation("org.jsoup:jsoup:1.24.1")'
                      '\n+implementation("org.jsoup:jsoup:1.24.2")'}
        ]
        self.assertEqual(len(sync.dependency_edits(40)), 1)
        api.return_value.append({"filename": "gradle/wrapper/gradle-wrapper.jar",
                                 "status": "modified"})
        with self.assertRaises(ValueError):
            sync.dependency_edits(40)

    @patch("scripts.sync_beta_dependencies.api")
    def test_single_commit_contains_only_version_files(self, api):
        old = 'version = "0.3.0"\nimplementation("org.jsoup:jsoup:1.24.1")\n'
        encoded = base64.b64encode(old.encode()).decode()
        calls = []

        def backend(repo, path, *, token, method="GET", payload=None):
            calls.append((repo, path, token, method, payload))
            if path == "/git/ref/heads/main":
                return {"object": {"sha": "a" * 40}}
            if path == "/git/commits/" + "a" * 40:
                return {"tree": {"sha": "b" * 40}}
            if path.startswith("/contents/"):
                return {"encoding": "base64", "content": encoded}
            if path == "/git/blobs":
                return {"sha": "c" * 40}
            if path == "/git/trees":
                return {"sha": "d" * 40}
            if path == "/git/commits":
                return {"sha": "e" * 40}
            if path == "/git/refs/heads/main":
                return {"object": {"sha": "e" * 40}}
            raise AssertionError(path)

        api.side_effect = backend
        sync.promote(41, {"composeApp/build.gradle.kts": [
            ('implementation("org.jsoup:jsoup:1.24.1")',
             'implementation("org.jsoup:jsoup:1.24.2")')
        ]})
        write_calls = [x for x in calls if x[3] != "GET"]
        self.assertEqual([x[1] for x in write_calls],
                         ["/git/blobs", "/git/trees", "/git/commits",
                          "/git/refs/heads/main"])
        self.assertEqual(write_calls[-1][4]["force"], False)
        tree = write_calls[1][4]["tree"]
        self.assertEqual([x["path"] for x in tree], ["composeApp/build.gradle.kts"])
        blob = write_calls[0][4]["content"]
        next_content = base64.b64decode(blob).decode()
        self.assertIn('version = "0.3.0"', next_content)
        self.assertIn('jsoup:1.24.2', next_content)

    @patch("scripts.sync_beta_dependencies.promote")
    @patch("scripts.sync_beta_dependencies.dependency_edits")
    @patch("scripts.sync_beta_dependencies.checked_merge", return_value=False)
    @patch("scripts.sync_beta_dependencies.api")
    @patch("scripts.sync_beta_dependencies.beta.webhook_pr_number", return_value=17)
    def test_no_promotion_without_verified_ci(self, webhook, api, checks, changes, promote):
        api.side_effect = [
            {"state": "closed", "merged_at": "2026-11-23T10:00:00Z",
             "number": 17, "user": {"login": "renovate[bot]"},
             "base": {"ref": "main"},
             "head": {"sha": "a" * 40, "repo": {"full_name": sync.BETA}},
             "merge_commit_sha": "b" * 40},
            {"status": "ahead"}
        ]
        sync.main()
        changes.assert_not_called()
        promote.assert_not_called()

    def test_workflow_is_trusted_and_uses_only_sync_token(self):
        config = Path(".github/workflows/beta-dependency-sync.yml").read_text()
        self.assertIn("repository_dispatch:", config)
        self.assertIn("environment: relay-control", config)
        self.assertIn("secrets.RELEASE_SYNC_TOKEN", config)
        self.assertIn("secrets.BETA_CI_TOKEN", config)
        self.assertNotIn("pull_request:", config)
        self.assertNotIn("repository: clcocd/GallFlowProject-Beta", config)


if __name__ == "__main__":
    unittest.main()
