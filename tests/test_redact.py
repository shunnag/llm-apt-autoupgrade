"""Nothing leaves the host with credentials still in it."""

from __future__ import annotations

import unittest

from aptai.redact import PLACEHOLDER, is_forbidden_path, redact, redact_obj


class TestRedact(unittest.TestCase):
    def test_repository_credentials(self):
        out = redact("deb https://alice:s3cr3t@repo.example.com/debian trixie main")
        self.assertNotIn("s3cr3t", out)
        self.assertNotIn("alice", out)
        self.assertIn("repo.example.com", out)

    def test_anthropic_key(self):
        self.assertNotIn("sk-ant-api03-", redact("key=sk-ant-api03-AAAABBBBCCCCDDDD"))

    def test_slack_webhook_path(self):
        out = redact("https://hooks.slack.com/services/T00000000/B11111111/abcdefghijklmnop")
        self.assertNotIn("abcdefghijklmnop", out)
        self.assertIn("hooks.slack.com", out)

    def test_mattermost_webhook_path(self):
        out = redact("https://mm.example.com/hooks/abcdefghijklmnop1234")
        self.assertNotIn("abcdefghijklmnop1234", out)

    def test_bearer_token(self):
        self.assertNotIn("abcdef1234567890", redact("Authorization: Bearer abcdef1234567890"))

    def test_key_value_secrets(self):
        for line in ['password = "hunter2hunter2"', "token: abcd1234efgh", "API_KEY=zzzzzzzzzzzz"]:
            with self.subTest(line=line):
                self.assertIn(PLACEHOLDER, redact(line))

    def test_github_and_aws_tokens(self):
        self.assertNotIn("ghp_", redact("ghp_" + "a" * 36))
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", redact("AKIAIOSFODNN7EXAMPLE"))

    def test_ordinary_lines_are_untouched(self):
        line = "deb http://archive.ubuntu.com/ubuntu noble-security main restricted"
        self.assertEqual(line, redact(line))

    def test_apt_error_lines_are_untouched(self):
        line = "E: Sub-process /usr/bin/dpkg returned an error code (1)"
        self.assertEqual(line, redact(line))

    def test_empty_input(self):
        self.assertEqual("", redact(None))
        self.assertEqual("", redact(""))

    def test_nested_structures(self):
        data = {"a": ["https://u:p@h/x"], "b": {"c": "token=abcdefghijkl"}, "d": 5}
        out = redact_obj(data)
        self.assertNotIn("u:p", out["a"][0])
        self.assertIn(PLACEHOLDER, out["b"]["c"])
        self.assertEqual(5, out["d"])


class TestForbiddenPaths(unittest.TestCase):
    def test_auth_conf_is_never_read(self):
        for path in ["/etc/apt/auth.conf", "/etc/apt/auth.conf.d/private.conf",
                     "/root/.netrc", "/etc/aptai/env", "/etc/aptai/api_key"]:
            with self.subTest(path=path):
                self.assertTrue(is_forbidden_path(path))

    def test_ordinary_sources_are_readable(self):
        for path in ["/etc/apt/sources.list", "/etc/apt/sources.list.d/x.sources",
                     "/var/log/dpkg.log"]:
            with self.subTest(path=path):
                self.assertFalse(is_forbidden_path(path))


if __name__ == "__main__":
    unittest.main()
