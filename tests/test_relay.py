import json
import os
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import relay


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.source = relay.SOURCES["beta"]
        self.item = {"head": "a" * 40, "base": "b" * 40, "merge": "c" * 40, "conflict": False}

    @patch.dict(os.environ, {"RELAY_DISPATCH_SECRET": "local-fixture-key" * 4})
    def test_dispatch_is_bound_to_type_number_and_concurrency_key(self):
        envelope = json.dumps({
            "source": "beta", "pr": 21, "event": "ci-relay-pr",
            "delivery": "f" * 36, "issued": int(time.time()),
        })
        event = {
            "action": "ci-relay-pr",
            "client_payload": {
                "envelope": envelope, "signature": relay.dispatch_signature(envelope), "key": "beta-21",
            },
        }
        self.assertEqual(relay.authenticate(event)["pr"], 21)
        event["client_payload"]["key"] = "beta-22"
        with self.assertRaises(ValueError):
            relay.authenticate(event)
        event["client_payload"]["key"] = "beta-21"
        event["client_payload"]["envelope"] = envelope.replace("21", "22", 1)
        with self.assertRaises(ValueError):
            relay.authenticate(event)

    @patch.dict(os.environ, {"RELAY_DISPATCH_SECRET": "local-fixture-key" * 4})
    def test_dcr_dispatch_uses_dedicated_event_type(self):
        envelope = json.dumps({
            "source": "dcr", "pr": 44, "event": "ci-relay-dcr-pr",
            "delivery": "f" * 36, "issued": int(time.time()),
        })
        event = {
            "action": "ci-relay-dcr-pr",
            "client_payload": {
                "envelope": envelope, "signature": relay.dispatch_signature(envelope), "key": "dcr-44",
            },
        }
        self.assertEqual(relay.authenticate(event)["pr"], 44)
        event["action"] = "ci-relay-pr"
        with self.assertRaises(ValueError):
            relay.authenticate(event)

    @patch.dict(os.environ, {
        "RELAY_DISPATCH_SECRET": "local-fixture-key" * 4,
        "GITHUB_REPOSITORY": "clcocd/ci-relay-hub",
    })
    @patch("scripts.relay.request")
    def test_dcr_base_redispatches_with_dedicated_pr_event(self, request):
        relay.send_pr("dcr", 44, "f" * 36)
        self.assertEqual(request.call_args.args[0], "/repos/clcocd/ci-relay-hub/dispatches")
        self.assertEqual(request.call_args.kwargs["payload"]["event_type"], "ci-relay-dcr-pr")

    def test_pr_verification_uses_only_a_private_checkout_for_source(self):
        workflow = Path(".github/workflows/ci-relay.yml").read_text(encoding="utf-8")
        pr_workflow = workflow.split("\n  release_build:\n", 1)[0]
        verify = pr_workflow.split("\n  verify:\n", 1)[1].split("\n  finish:\n", 1)[0]
        self.assertIn("repository: ${{ matrix.repository }}", verify)
        self.assertIn("token: ${{ secrets[matrix.checkout_secret] }}", verify)
        self.assertIn("persist-credentials: false", verify)
        self.assertNotIn("DCR_READ_TOKEN", pr_workflow)
        self.assertNotIn("scripts/relay.py publish", pr_workflow)
        self.assertNotIn("relay-snapshots/", pr_workflow)
        self.assertNotIn("upload-artifact", verify)

    @patch.dict(os.environ, {"CI_RELAY_PUBLIC_SOURCE": "beta,dcr"})
    @patch("scripts.relay.require_protection")
    @patch("scripts.relay.source_api", return_value={"enabled": False})
    @patch("scripts.relay.status")
    @patch("scripts.relay.already_verified", return_value=False)
    @patch("scripts.relay.matching", return_value=True)
    @patch("scripts.relay.current_snapshot")
    @patch("scripts.relay.emit")
    def test_prepare_selects_the_correct_repository_and_checkout_secret(
        self, emit, snapshot, matching, verified, status, api, protection
    ):
        snapshot.return_value = self.item
        for alias, repository, secret in (
            ("beta", "clcocd/GallFlowProject-Beta", "BETA_CI_TOKEN"),
            ("dcr", "clcocd/DCR-Kotlin", "DCR_CI_TOKEN"),
        ):
            with self.subTest(source=alias):
                emit.reset_mock()
                with patch("scripts.relay.event_data", return_value={"source": alias, "pr": 105}):
                    relay.prepare()
                outputs = dict(call.args for call in emit.call_args_list)
                self.assertEqual(outputs["pr"], 105)
                for runner in json.loads(outputs["matrix"])["include"]:
                    self.assertEqual(runner["repository"], repository)
                    self.assertEqual(runner["checkout_secret"], secret)

    def test_dcr_release_uses_existing_ci_token_only_for_publishing(self):
        workflow = Path(".github/workflows/ci-relay.yml").read_text(encoding="utf-8")
        self.assertIn("\n  release_build:\n", workflow)
        self.assertIn("\n  release_publish:\n", workflow)
        build = workflow.split("\n  release_build:\n", 1)[1].split("\n  release_publish:\n", 1)[0]
        publishing = workflow.split("\n  release_publish:\n", 1)[1]
        self.assertNotIn("DCR_RELEASE_TOKEN", workflow)
        self.assertIn("GH_TOKEN: ${{ secrets.DCR_CI_TOKEN }}", publishing)
        self.assertEqual(relay.SOURCES["dcr"]["control_token"], "DCR_CI_TOKEN")
        self.assertIn("--repo clcocd/DCR-Kotlin", publishing)
        self.assertIn("actions/download-artifact@v4", publishing)
        self.assertIn("github.event.action == 'ci-relay-dcr-base'", build)
        self.assertIn("vars.CI_RELAY_PUBLIC_SOURCE != 'off'", build)
        self.assertNotIn("vars.CI_RELAY_PUBLIC_SOURCE != ''", build)

    @patch.dict(os.environ, {"CI_RELAY_PUBLIC_SOURCE": ""})
    def test_dcr_webhook_pr_runs_without_a_separate_opt_in_variable(self):
        self.assertEqual(relay.require_enrolled("dcr")["repository"], "clcocd/DCR-Kotlin")
        with self.assertRaises(RuntimeError):
            relay.require_enrolled("beta")

    @patch.dict(os.environ, {"CI_RELAY_PUBLIC_SOURCE": "off"})
    def test_dcr_webhook_pr_can_be_explicitly_disabled(self):
        with self.assertRaises(RuntimeError):
            relay.require_enrolled("dcr")

    @patch.dict(os.environ, {"CI_RELAY_PUBLIC_SOURCE": "beta,dcr"})
    def test_hub_enrolls_multiple_projects_with_isolated_profiles(self):
        self.assertEqual(relay.require_enrolled("beta")["repository"], "clcocd/GallFlowProject-Beta")
        dcr = relay.require_enrolled("dcr")
        self.assertEqual(dcr["repository"], "clcocd/DCR-Kotlin")
        self.assertEqual(dcr["contexts"], ("ci-relay/Linux",))
        self.assertEqual(dcr["runners"][0]["profile"], "dcr")

    @patch.dict(os.environ, {"BETA_CI_TOKEN": "b-token", "DCR_CI_TOKEN": "d-token"})
    @patch("scripts.relay.request", return_value={"ok": True})
    def test_source_tokens_are_isolated(self, request):
        relay.source_api(relay.SOURCES["beta"], "/pulls")
        request.assert_called_with("/repos/clcocd/GallFlowProject-Beta/pulls", "BETA_CI_TOKEN")
        relay.source_api(relay.SOURCES["dcr"], "/pulls")
        request.assert_called_with("/repos/clcocd/DCR-Kotlin/pulls", "DCR_CI_TOKEN")
        relay.source_api(relay.SOURCES["dcr"], "/statuses/" + "a" * 40, token="status")
        request.assert_called_with("/repos/clcocd/DCR-Kotlin/statuses/" + "a" * 40, "DCR_CI_TOKEN")

    @patch("scripts.relay.source_api")
    def test_release_version_reads_pinned_source(self, api):
        import base64
        api.return_value = {
            "content": base64.b64encode(b'{"version":"6.3.0.4"}').decode()
        }
        source = relay.SOURCES["dcr"]
        self.assertEqual(relay.release_version(source, "a" * 40), "6.3.0.4")
        api.assert_called_once_with(source, "/contents/package.json?ref=" + "a" * 40)

    @patch.dict(os.environ, {"SOURCE_SHA": "a" * 40,
                              "RELEASE_VERSION": "6.3.0.4",
                              "RELEASE_TAG": "v6.3.0.4-kotlin-test",
                              "CI_RELAY_PUBLIC_SOURCE": "dcr"})
    @patch("scripts.relay.event_data", return_value={"source": "dcr"})
    @patch("scripts.relay.base_sha", return_value="b" * 40)
    def test_private_release_cannot_publish_stale_main(self, base, event):
        with self.assertRaises(RuntimeError):
            relay.release_verify()

    @patch.dict(os.environ, {"CI_RELAY_PUBLIC_SOURCE": ""})
    @patch("scripts.relay.event_data", return_value={"source": "dcr"})
    @patch("scripts.relay.base_sha", return_value="a" * 40)
    @patch("scripts.relay.release_version", return_value="6.3.0.4")
    @patch("scripts.relay.release_missing", return_value=True)
    @patch("scripts.relay.emit")
    def test_dcr_release_gate_emits_private_version_metadata(self, emit, unused, version, base, event):
        relay.release_gate()
        self.assertEqual(emit.call_count, 4)
        self.assertEqual(emit.call_args_list[-1].args, ("tag", "v6.3.0.4-kotlin-test"))

    @patch.dict(os.environ, {"CI_RELAY_PUBLIC_SOURCE": "off"})
    @patch("scripts.relay.event_data", return_value={"source": "dcr"})
    @patch("scripts.relay.base_sha")
    def test_dcr_release_can_be_explicitly_disabled(self, base, event):
        with self.assertRaises(RuntimeError):
            relay.release_gate()
        base.assert_not_called()

    @patch.dict(os.environ, {"CI_RELAY_PUBLIC_SOURCE": "", "GITHUB_EVENT_PATH": "unused"})
    @patch("scripts.relay.event_data", return_value={"source": "dcr", "pr": 105})
    @patch("scripts.relay.source_api")
    @patch("scripts.relay.require_protection")
    @patch("scripts.relay.current_snapshot", return_value=None)
    def test_dcr_prepare_does_not_require_admin_permissions_before_ci(self, snapshot, protection, api, event):
        relay.prepare()
        snapshot.assert_called_once()
        protection.assert_not_called()
        api.assert_not_called()

    @patch.dict(os.environ, {"CI_RELAY_PUBLIC_SOURCE": "",
                              "CANDIDATE": '{"head":"' + "a" * 40 + '","base":"' + "b" * 40 + '","merge":"' + "c" * 40 + '","conflict":false}',
                              "PREPARE_RESULT": "success", "BUILD_RESULT": "success"})
    @patch("scripts.relay.event_data", return_value={"source": "dcr", "pr": 105})
    @patch("scripts.relay.matching", return_value=True)
    @patch("scripts.relay.current_snapshot")
    @patch("scripts.relay.status")
    @patch("scripts.relay.merge_dcr_tested")
    def test_dcr_finish_merges_only_after_success(self, merge, status, snapshot, matching, event):
        snapshot.return_value = self.item
        relay.finish()
        status.assert_called_once()
        self.assertEqual(status.call_args.args[2], "success")
        merge.assert_called_once_with(relay.SOURCES["dcr"], 105, self.item)

    @patch("scripts.relay.matching", return_value=True)
    @patch("scripts.relay.source_api")
    def test_dcr_auto_merge_publishes_only_tested_merge_without_force(self, api, matching):
        api.side_effect = [
            {"state": "open", "draft": False, "base": {"ref": "main"},
             "head": {"sha": self.item["head"]}, "merge_commit_sha": self.item["merge"],
             "user": {"login": "clcocd"}},
            {"parents": [{"sha": self.item["base"]}, {"sha": self.item["head"]}]},
            {"object": {"sha": self.item["merge"]}},
        ]
        relay.merge_dcr_tested(relay.SOURCES["dcr"], 105, self.item)
        self.assertEqual(api.call_args.args[1], "/git/refs/heads/main")
        self.assertEqual(api.call_args.kwargs, {
            "token": "control", "method": "PATCH",
            "payload": {"sha": self.item["merge"], "force": False},
        })

    @patch("scripts.relay.matching", return_value=True)
    @patch("scripts.relay.source_api")
    def test_dcr_deletes_unchanged_same_repo_branch_after_tested_merge(self, api, matching):
        source = relay.SOURCES["dcr"]
        pr = {"state": "open", "draft": False, "base": {"ref": "main"},
              "head": {"sha": self.item["head"], "ref": "fix/x-widget-retry",
                       "repo": {"full_name": source["repository"]}},
              "merge_commit_sha": self.item["merge"], "user": {"login": "clcocd"}}
        api.side_effect = [
            pr,
            {"parents": [{"sha": self.item["base"]}, {"sha": self.item["head"]}]},
            {"object": {"sha": self.item["merge"]}},
            {"object": {"sha": self.item["head"]}},
            None,
        ]
        relay.merge_dcr_tested(source, 105, self.item)
        self.assertEqual(api.call_count, 5)
        self.assertEqual(api.call_args.args, (source, "/git/refs/heads/fix/x-widget-retry"))
        self.assertEqual(api.call_args.kwargs, {"token": "control", "method": "DELETE"})

    @patch("scripts.relay.matching", return_value=True)
    @patch("scripts.relay.source_api")
    def test_dcr_does_not_delete_branch_when_head_changed(self, api, matching):
        source = relay.SOURCES["dcr"]
        pr = {"state": "open", "draft": False, "base": {"ref": "main"},
              "head": {"sha": self.item["head"], "ref": "feature/changed",
                       "repo": {"full_name": source["repository"]}},
              "merge_commit_sha": self.item["merge"], "user": {"login": "clcocd"}}
        api.side_effect = [
            pr,
            {"parents": [{"sha": self.item["base"]}, {"sha": self.item["head"]}]},
            {"object": {"sha": self.item["merge"]}},
            {"object": {"sha": "d" * 40}},
        ]
        relay.merge_dcr_tested(source, 105, self.item)
        self.assertEqual(api.call_count, 4)
        self.assertEqual(api.call_args.args, (source, "/git/ref/heads/feature/changed"))

    @patch("scripts.relay.matching", return_value=True)
    @patch("scripts.relay.source_api")
    def test_dcr_does_not_delete_fork_or_main_branch(self, api, matching):
        source = relay.SOURCES["dcr"]
        for name, repository in (("fork/change", "someone/DCR-Kotlin"), ("main", source["repository"])):
            with self.subTest(name=name):
                pr = {"state": "open", "draft": False, "base": {"ref": "main"},
                      "head": {"sha": self.item["head"], "ref": name,
                               "repo": {"full_name": repository}},
                      "merge_commit_sha": self.item["merge"], "user": {"login": "clcocd"}}
                api.reset_mock()
                api.side_effect = [
                    pr,
                    {"parents": [{"sha": self.item["base"]}, {"sha": self.item["head"]}]},
                    {"object": {"sha": self.item["merge"]}},
                ]
                relay.merge_dcr_tested(source, 105, self.item)
                self.assertEqual(api.call_count, 3)
                self.assertEqual(api.call_args.kwargs["method"], "PATCH")

    @patch("scripts.relay.matching", return_value=True)
    @patch("scripts.relay.source_api")
    def test_dcr_auto_merge_rejects_unexpected_merge_parents(self, api, matching):
        api.side_effect = [
            {"state": "open", "draft": False, "base": {"ref": "main"},
             "head": {"sha": self.item["head"]}, "merge_commit_sha": self.item["merge"],
             "user": {"login": "clcocd"}},
            {"parents": [{"sha": self.item["head"]}, {"sha": self.item["base"]}]},
        ]
        with self.assertRaises(RuntimeError):
            relay.merge_dcr_tested(relay.SOURCES["dcr"], 105, self.item)
        self.assertEqual(api.call_count, 2)

    @patch("scripts.relay.matching", return_value=True)
    @patch("scripts.relay.source_api", return_value={"user": {"login": "renovate[bot]"}})
    def test_dcr_auto_merge_leaves_renovate_pr_for_bot(self, api, matching):
        source = relay.SOURCES["dcr"]
        relay.merge_dcr_tested(source, 105, self.item)
        api.assert_called_once_with(source, "/pulls/105")

    @patch("scripts.relay.matching", return_value=False)
    @patch("scripts.relay.source_api")
    def test_dcr_auto_merge_does_not_write_if_base_or_head_changed(self, api, matching):
        relay.merge_dcr_tested(relay.SOURCES["dcr"], 105, self.item)
        api.assert_not_called()

    def test_dcr_protection_needs_only_its_own_ci_context(self):
        dcr = relay.SOURCES["dcr"]
        rule = {
            "required_status_checks": {"strict": True, "contexts": list(dcr["contexts"])},
            "enforce_admins": {"enabled": True},
            "allow_force_pushes": {"enabled": False},
            "allow_deletions": {"enabled": False},
        }
        self.assertTrue(relay.protection_allows_relay(rule, dcr))
        self.assertFalse(relay.protection_allows_relay(rule, self.source))

    def test_protection_must_be_strict_and_apply_to_admins(self):
        rule = {
            "required_status_checks": {"strict": True, "contexts": list(relay.CONTEXTS)},
            "enforce_admins": {"enabled": True},
            "allow_force_pushes": {"enabled": False},
            "allow_deletions": {"enabled": False},
        }
        self.assertTrue(relay.protection_allows_relay(rule))
        rule["enforce_admins"]["enabled"] = False
        self.assertFalse(relay.protection_allows_relay(rule))

    @patch("scripts.relay.source_api")
    @patch("scripts.relay.matching")
    @patch("scripts.relay.require_protection")
    def test_renovate_is_never_merged_by_relay(self, protection, matching, api):
        relay.merge_or_update(self.source, 1, {"user": {"login": "renovate[bot]"}}, self.item)
        api.assert_not_called()
        protection.assert_not_called()

    @patch("scripts.relay.source_api", side_effect=[{"behind_by": 0}, {"merged": True}])
    @patch("scripts.relay.matching", return_value=True)
    @patch("scripts.relay.require_protection")
    def test_ordinary_merge_requires_exact_head(self, protection, matching, api):
        relay.merge_or_update(self.source, 1, {"user": {"login": "contributor"}}, self.item)
        self.assertEqual(api.call_args.args, (self.source, "/pulls/1/merge"))
        self.assertEqual(api.call_args.kwargs["payload"]["sha"], self.item["head"])

    @patch("scripts.relay.source_api", return_value={"behind_by": 0})
    @patch("scripts.relay.matching", return_value=False)
    @patch("scripts.relay.require_protection")
    def test_stale_head_or_base_aborts_before_merge(self, protection, matching, api):
        relay.merge_or_update(self.source, 1, {"user": {"login": "contributor"}}, self.item)
        self.assertEqual(api.call_count, 1)


if __name__ == "__main__":
    unittest.main()
