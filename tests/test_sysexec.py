"""The child environment must not carry aptai's secrets into maintainer scripts."""

from __future__ import annotations

import os
import unittest
from unittest import mock

from aptai.sysexec import BASE_ENV, build_env, is_secret_env_key, run_command


class TestEnvironmentScrubbing(unittest.TestCase):
    def test_known_secret_names_are_dropped(self):
        secrets = {
            "ANTHROPIC_API_KEY": "sk-ant-test",
            "APTAI_SLACK_WEBHOOK": "https://hooks.slack.com/services/A/B/C",
            "APTAI_MATTERMOST_WEBHOOK": "https://mm.example.com/hooks/x",
            "ANTHROPIC_AUTH_TOKEN": "t",
        }
        with mock.patch.dict(os.environ, secrets, clear=False):
            env = build_env()
        for name in secrets:
            self.assertNotIn(name, env, f"{name} leaked into the child environment")

    def test_secret_shaped_names_are_dropped(self):
        extra = {"COMPANY_API_KEY": "x", "OPS_WEBHOOK": "y", "DB_PASSWORD": "z",
                 "SOME_TOKEN": "t", "MY_SECRET": "s"}
        with mock.patch.dict(os.environ, extra, clear=False):
            env = build_env()
        for name in extra:
            self.assertNotIn(name, env)

    def test_ordinary_variables_survive(self):
        with mock.patch.dict(os.environ, {"PATH": "/usr/bin", "HOME": "/root"}, clear=False):
            env = build_env()
        self.assertEqual("/usr/bin", env["PATH"])
        self.assertEqual("/root", env["HOME"])

    def test_apt_frontend_variables_are_forced(self):
        env = build_env()
        for key, value in BASE_ENV.items():
            self.assertEqual(value, env[key])

    def test_needrestart_mode(self):
        self.assertEqual("l", build_env(needrestart_mode="l")["NEEDRESTART_MODE"])

    def test_key_classification(self):
        for name in ["ANTHROPIC_API_KEY", "x_token", "A_WEBHOOK", "b_secret", "P_PASSWORD"]:
            self.assertTrue(is_secret_env_key(name), name)
        for name in ["PATH", "HOME", "LANG", "KEYBOARD", "TOKENIZER"]:
            self.assertFalse(is_secret_env_key(name), name)


class TestRunCommand(unittest.TestCase):
    def test_missing_executable_is_reported_not_raised(self):
        result = run_command(["/nonexistent/aptai-test-binary"], timeout=5)
        self.assertTrue(result.not_found)
        self.assertFalse(result.ok)
        self.assertEqual(127, result.returncode)

    def test_argv_must_be_a_list_of_strings(self):
        for argv in ([], ["ok", 5], "echo hi"):
            with self.subTest(argv=argv):
                with self.assertRaises(ValueError):
                    run_command(argv)

    def test_exit_status_is_captured_not_raised(self):
        result = run_command(["/bin/sh", "-c", "echo out; echo err >&2; exit 3"], timeout=10)
        self.assertEqual(3, result.returncode)
        self.assertIn("out", result.stdout)
        self.assertIn("err", result.stderr)
        self.assertFalse(result.ok)

    def test_timeout_is_captured_not_raised(self):
        result = run_command(["/bin/sh", "-c", "sleep 5"], timeout=0.3)
        self.assertTrue(result.timed_out)
        self.assertFalse(result.ok)

    def test_output_is_tail_truncated(self):
        result = run_command(["/bin/sh", "-c", "printf 'x%.0s' $(seq 1 5000)"], timeout=20)
        self.assertLess(len(result.combined_output(1000)), 1100)


if __name__ == "__main__":
    unittest.main()
