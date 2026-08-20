"""Loop control: the runner must not spin on an unchanging failure."""

from __future__ import annotations

import unittest

from aptai.runner import error_signature


class TestErrorSignature(unittest.TestCase):
    def test_identical_failures_share_a_signature(self):
        first = "E: Sub-process /usr/bin/dpkg returned an error code (1)\nSetting up nginx (1.24)"
        second = "E: Sub-process /usr/bin/dpkg returned an error code (1)\nSetting up nginx (1.25)"
        self.assertEqual(error_signature(first), error_signature(second))

    def test_digits_are_normalised(self):
        self.assertEqual(
            error_signature("E: You have held broken packages (17)"),
            error_signature("E: You have held broken packages (23)"),
        )

    def test_different_failures_differ(self):
        self.assertNotEqual(
            error_signature("E: Unable to fetch some archives"),
            error_signature("E: Unmet dependencies. Try 'apt --fix-broken install'"),
        )

    def test_line_order_does_not_matter(self):
        self.assertEqual(
            error_signature("E: alpha\nE: beta"),
            error_signature("E: beta\nE: alpha"),
        )

    def test_falls_back_to_the_tail_when_no_error_lines(self):
        signature = error_signature("some output\nwithout error markers")
        self.assertTrue(signature)

    def test_empty_text(self):
        self.assertEqual("", error_signature(""))


class TestStageWiring(unittest.TestCase):
    def test_every_stage_has_an_action_vocabulary(self):
        from aptai.plan import STAGE_ACTIONS
        from aptai.runner import STAGES

        for stage in STAGES:
            self.assertIn(stage.key, STAGE_ACTIONS, f"{stage.key} has no vocabulary")

    def test_every_stage_has_an_executor_method(self):
        from aptai.executor import Executor
        from aptai.runner import STAGES

        mapping = {
            "update": "apt_update",
            "full_upgrade": "apt_full_upgrade",
            "autoremove": "apt_autoremove",
            "autoclean": "apt_autoclean",
        }
        for stage in STAGES:
            self.assertIn(stage.key, mapping)
            self.assertTrue(hasattr(Executor, mapping[stage.key]))

    def test_every_stage_has_a_config_switch(self):
        from aptai.config import AptConfig
        from aptai.runner import STAGES

        for stage in STAGES:
            self.assertTrue(hasattr(AptConfig, stage.enabled_attr))


if __name__ == "__main__":
    unittest.main()
