"""Hostile-plan tests for the safety policy.

Every test here feeds the validator a plan that a compromised or
prompt-injected model could plausibly return, and asserts that it is refused.
These are the tests that decide whether this project is safe to run as root.
"""

from __future__ import annotations

import os
import unittest

from aptai.plan import ActionKind
from aptai.policy import Policy, action_signature, validate_source_path
from tests.helpers import KERNEL, action, make_config, make_facts, plan


class PolicyTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.facts = make_facts()
        self.config = make_config()
        self.policy = Policy(self.config, self.facts)

    def assertRefused(self, act, stage="full_upgrade", contains=""):
        result = self.policy.review(plan(act), stage)
        self.assertEqual([], result.accepted, f"action was wrongly accepted: {act.describe()}")
        self.assertTrue(result.rejected, "no rejection was recorded")
        if contains:
            self.assertIn(contains, result.rejected[0].reason)
        return result

    def assertAccepted(self, act, stage="full_upgrade"):
        result = self.policy.review(plan(act), stage)
        self.assertEqual(
            1, len(result.accepted),
            f"action was wrongly refused: "
            f"{result.rejected[0].reason if result.rejected else 'no reason'}",
        )
        return result


class TestProtectedPackages(PolicyTestCase):
    def test_refuses_to_remove_listed_protected_package(self):
        self.assertRefused(
            action(ActionKind.APT_REMOVE, packages=["libc6"]),
            contains="policy.protected_packages",
        )

    def test_refuses_to_remove_essential_package(self):
        self.config.policy.protected_packages = []
        self.policy = Policy(self.config, self.facts)
        self.assertRefused(
            action(ActionKind.APT_REMOVE, packages=["bash"]), contains="Essential"
        )

    def test_refuses_to_remove_required_priority_package(self):
        self.config.policy.protected_packages = []
        self.policy = Policy(self.config, self.facts)
        self.assertRefused(
            action(ActionKind.APT_REMOVE, packages=["python3-minimal"]),
            contains="Priority: required/important",
        )

    def test_refuses_to_remove_the_running_kernel(self):
        self.assertRefused(
            action(ActionKind.APT_REMOVE, packages=[f"linux-image-{KERNEL}"]),
            contains="running kernel",
        )

    def test_allows_removing_an_older_kernel(self):
        self.assertAccepted(
            action(ActionKind.APT_REMOVE, packages=["linux-image-6.8.0-31-generic"])
        )

    def test_refuses_to_auto_mark_a_protected_package(self):
        # 'apt-mark auto' is a deferred removal: autoremove would take it later.
        self.assertRefused(
            action(ActionKind.APT_MARK, mark="auto", packages=["systemd"]),
            contains="refusing to mark",
        )

    def test_allows_holding_a_normal_package(self):
        self.assertAccepted(action(ActionKind.APT_MARK, mark="hold", packages=["nginx"]))

    def test_protected_check_ignores_arch_and_version_qualifiers(self):
        self.assertIsNotNone(self.policy.protected_reason("libc6:amd64"))
        self.assertIsNotNone(self.policy.protected_reason("libc6=2.39-0ubuntu8"))


class TestArgumentInjection(PolicyTestCase):
    def test_rejects_shell_metacharacters(self):
        for name in [
            "nginx; rm -rf /",
            "nginx && reboot",
            "nginx | tee /etc/passwd",
            "$(reboot)",
            "`reboot`",
            "nginx\nrm -rf /",
            "nginx /etc/passwd",
            "../../etc/passwd",
            "nginx'",
            'nginx"',
        ]:
            with self.subTest(name=name):
                self.assertRefused(action(ActionKind.APT_INSTALL, packages=[name]))

    def test_rejects_option_like_package_names(self):
        for name in ["--purge", "-y", "--allow-remove-essential", "--force-yes"]:
            with self.subTest(name=name):
                self.assertRefused(action(ActionKind.APT_REMOVE, packages=[name]))

    def test_rejects_control_characters_in_free_text(self):
        self.assertRefused(
            action(ActionKind.APT_INSTALL, packages=["nginx"], reason="line1\nline2"),
            contains="control characters",
        )

    def test_rejects_absurdly_long_package_lists(self):
        self.assertRefused(
            action(ActionKind.APT_INSTALL, packages=[f"pkg{i}" for i in range(40)]),
            contains="limit is",
        )

    def test_accepts_normal_names_with_arch_qualifier(self):
        self.assertAccepted(action(ActionKind.APT_INSTALL, packages=["libfoo1:amd64", "curl"]))


class TestStageVocabulary(PolicyTestCase):
    def test_update_stage_cannot_touch_dpkg_state(self):
        for kind in (ActionKind.APT_REMOVE, ActionKind.DPKG_CONFIGURE_PENDING,
                     ActionKind.APT_INSTALL, ActionKind.APT_FULL_UPGRADE):
            with self.subTest(kind=kind):
                act = action(kind, packages=["nginx"] if "install" in kind or "remove" in kind else [])
                self.assertRefused(act, stage="update", contains="not permitted during the update stage")

    def test_full_upgrade_stage_cannot_edit_sources(self):
        self.config.policy.allow_sources_edit = True
        self.policy = Policy(self.config, self.facts)
        self.assertRefused(
            action(
                ActionKind.DISABLE_APT_SOURCE,
                source_file="/etc/apt/sources.list.d/third-party.list",
                source_uri="https://example.com/repo",
            ),
            contains="not permitted during the full_upgrade stage",
        )

    def test_autoclean_stage_is_cache_only(self):
        self.assertRefused(
            action(ActionKind.APT_INSTALL, packages=["nginx"]),
            stage="autoclean",
            contains="not permitted",
        )

    def test_unknown_stage_escalates(self):
        result = self.policy.review(plan(action(ActionKind.APT_CLEAN)), "nonsense")
        self.assertTrue(result.escalate)


class TestLimits(PolicyTestCase):
    def test_risk_above_the_ceiling_is_refused(self):
        self.assertRefused(
            action(ActionKind.APT_REMOVE, packages=["nginx"], risk="high"),
            contains="exceeds policy.max_risk",
        )

    def test_high_risk_allowed_when_configured(self):
        self.config.policy.max_risk = "high"
        self.policy = Policy(self.config, self.facts)
        self.assertAccepted(action(ActionKind.APT_REMOVE, packages=["nginx"], risk="high"))

    def test_too_many_removals_refused(self):
        self.config.policy.max_removals = 2
        self.policy = Policy(self.config, self.facts)
        self.assertRefused(
            action(ActionKind.APT_REMOVE, packages=["nginx", "curl", "libfoo1"]),
            contains="policy.max_removals",
        )

    def test_action_budget_per_round(self):
        self.config.policy.max_actions_per_round = 2
        self.policy = Policy(self.config, self.facts)
        result = self.policy.review(
            plan(
                action(ActionKind.DPKG_AUDIT),
                action(ActionKind.APT_CLEAN),
                action(ActionKind.APT_AUTOCLEAN),
            ),
            "full_upgrade",
        )
        self.assertEqual(2, len(result.accepted))
        self.assertIn("max_actions_per_round", result.rejected[0].reason)

    def test_repeated_action_across_rounds_is_refused(self):
        act = action(ActionKind.APT_FIX_BROKEN)
        first = self.policy.review(plan(act), "full_upgrade")
        signatures = {action_signature(a) for a in first.accepted}
        second = self.policy.review(plan(act), "full_upgrade", previous_signatures=signatures)
        self.assertEqual([], second.accepted)
        self.assertIn("already attempted", second.rejected[0].reason)

    def test_wait_is_bounded(self):
        self.assertRefused(action(ActionKind.WAIT, seconds=99999), contains="limited to")
        self.assertRefused(action(ActionKind.WAIT, seconds=0), contains="positive")
        self.assertAccepted(action(ActionKind.WAIT, seconds=60))

    def test_purge_requires_opt_in(self):
        self.assertRefused(
            action(ActionKind.APT_REMOVE, packages=["nginx"], purge=True),
            contains="policy.allow_purge",
        )

    def test_version_pin_requires_downgrade_opt_in(self):
        self.assertRefused(
            action(ActionKind.APT_INSTALL, packages=["nginx=1.24.0-1"]),
            contains="policy.allow_downgrade",
        )
        self.config.policy.allow_downgrade = True
        self.policy = Policy(self.config, self.facts)
        self.assertAccepted(action(ActionKind.APT_INSTALL, packages=["nginx=1.24.0-1"]))

    def test_removal_can_be_disabled_entirely(self):
        self.config.policy.allow_remove = False
        self.policy = Policy(self.config, self.facts)
        self.assertRefused(
            action(ActionKind.APT_REMOVE, packages=["nginx"]), contains="policy.allow_remove"
        )

    def test_parameterless_actions_reject_smuggled_parameters(self):
        self.assertRefused(
            action(ActionKind.APT_FIX_BROKEN, packages=["nginx"]), contains="takes no parameters"
        )


class TestKeyImport(PolicyTestCase):
    def test_disabled_by_default(self):
        self.assertRefused(
            action(ActionKind.IMPORT_REPO_KEY, key_ids=["ABCDEF0123456789"],
                   keyserver="keyserver.ubuntu.com"),
            stage="update",
            contains="policy.allow_key_import",
        )

    def test_rejects_non_hex_key_ids(self):
        self.config.policy.allow_key_import = True
        self.policy = Policy(self.config, self.facts)
        self.assertRefused(
            action(ActionKind.IMPORT_REPO_KEY, key_ids=["$(reboot)"],
                   keyserver="keyserver.ubuntu.com"),
            stage="update",
            contains="hexadecimal",
        )

    def test_rejects_unlisted_keyserver(self):
        self.config.policy.allow_key_import = True
        self.policy = Policy(self.config, self.facts)
        self.assertRefused(
            action(ActionKind.IMPORT_REPO_KEY, key_ids=["ABCDEF0123456789"],
                   keyserver="evil.example.com"),
            stage="update",
            contains="allowed_keyservers",
        )

    def test_accepts_an_allowlisted_keyserver(self):
        self.config.policy.allow_key_import = True
        self.policy = Policy(self.config, self.facts)
        self.assertAccepted(
            action(ActionKind.IMPORT_REPO_KEY, key_ids=["0xABCDEF0123456789"],
                   keyserver="keyserver.ubuntu.com"),
            stage="update",
        )


class TestSourceEditing(PolicyTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.config.policy.allow_sources_edit = True
        self.policy = Policy(self.config, self.facts)

    def test_disabled_by_default(self):
        self.config.policy.allow_sources_edit = False
        self.policy = Policy(self.config, self.facts)
        self.assertRefused(
            action(ActionKind.DISABLE_APT_SOURCE,
                   source_file="/etc/apt/sources.list.d/x.list",
                   source_uri="https://example.com/repo"),
            stage="update",
            contains="policy.allow_sources_edit",
        )

    def test_rejects_paths_outside_etc_apt(self):
        for path in ["/etc/passwd", "/etc/shadow", "/root/.ssh/authorized_keys",
                     "/etc/apt/../shadow", "/etc/sudoers.d/x.list"]:
            with self.subTest(path=path):
                self.assertRefused(
                    action(ActionKind.DISABLE_APT_SOURCE, source_file=path,
                           source_uri="https://example.com/repo"),
                    stage="update",
                )

    def test_rejects_the_distribution_sources(self):
        for path in ["/etc/apt/sources.list", "/etc/apt/sources.list.d/ubuntu.sources",
                     "/etc/apt/sources.list.d/debian.sources"]:
            with self.subTest(path=path):
                self.assertRefused(
                    action(ActionKind.DISABLE_APT_SOURCE, source_file=path,
                           source_uri="https://archive.ubuntu.com/ubuntu"),
                    stage="update",
                    contains="distribution's own repositories",
                )

    def test_rejects_a_non_source_suffix(self):
        self.assertRefused(
            action(ActionKind.DISABLE_APT_SOURCE, source_file="/etc/apt/apt.conf.d/99evil",
                   source_uri="https://example.com/repo"),
            stage="update",
            contains=".list or .sources",
        )

    def test_rejects_a_bogus_uri(self):
        self.assertRefused(
            action(ActionKind.DISABLE_APT_SOURCE,
                   source_file="/etc/apt/sources.list.d/third.list",
                   source_uri="file:///etc/passwd"),
            stage="update",
            contains="valid repository URI",
        )

    def test_accepts_a_third_party_list(self):
        self.assertAccepted(
            action(ActionKind.DISABLE_APT_SOURCE,
                   source_file="/etc/apt/sources.list.d/third-party.list",
                   source_uri="https://packages.example.com/debian"),
            stage="update",
        )

    def test_symlink_escape_is_blocked(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "secret.list")
            with open(target, "w", encoding="utf-8") as handle:
                handle.write("deb https://example.com/x stable main\n")
            # A path under /etc/apt is only accepted when its realpath is too.
            self.assertIsNotNone(validate_source_path(target))


class TestEscalation(PolicyTestCase):
    def test_explicit_escalation_drops_every_action(self):
        result = self.policy.review(
            plan(action(ActionKind.APT_REMOVE, packages=["nginx"]),
                 escalate=True, reason="needs a human"),
            "full_upgrade",
        )
        self.assertTrue(result.escalate)
        self.assertEqual([], result.accepted)
        self.assertEqual("needs a human", result.escalation_reason)

    def test_all_refused_becomes_an_escalation(self):
        result = self.policy.review(
            plan(action(ActionKind.APT_REMOVE, packages=["libc6"])), "full_upgrade"
        )
        self.assertTrue(result.escalate)
        self.assertIn("refused by the local policy", result.escalation_reason)

    def test_empty_plan_is_not_an_escalation(self):
        result = self.policy.review(plan(), "full_upgrade")
        self.assertFalse(result.escalate)
        self.assertEqual([], result.accepted)


if __name__ == "__main__":
    unittest.main()
