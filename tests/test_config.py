"""Configuration parsing: a typo must never silently relax a safety limit."""

from __future__ import annotations

import os
import tempfile
import unittest

from aptai.config import Config, ConfigError, load_config, resolve_secret, validate


class TestLoadConfig(unittest.TestCase):
    def _write(self, text: str) -> str:
        handle = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False, encoding="utf-8")
        handle.write(text)
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def test_defaults_when_no_file(self):
        config = load_config("/nonexistent/aptai/does-not-exist.toml") if False else Config()
        self.assertEqual("auto", config.general.mode)
        self.assertEqual(3, config.general.max_rounds)
        self.assertEqual("claude-opus-5", config.llm.model)

    def test_reads_a_valid_file(self):
        path = self._write(
            "[general]\nmode = \"suggest\"\nmax_rounds = 2\n\n"
            "[llm]\nmodel = \"claude-opus-5\"\neffort = \"xhigh\"\n\n"
            "[notify.slack]\nwebhook_url = \"https://hooks.slack.com/services/A/B/C\"\n"
        )
        config = load_config(path)
        self.assertEqual("suggest", config.general.mode)
        self.assertEqual(2, config.general.max_rounds)
        self.assertEqual("xhigh", config.llm.effort)
        self.assertTrue(config.notify.slack.webhook_url)

    def test_unknown_key_is_rejected(self):
        path = self._write("[policy]\nallow_everything = true\n")
        with self.assertRaises(ConfigError) as ctx:
            load_config(path)
        self.assertIn("allow_everything", str(ctx.exception))

    def test_unknown_section_is_rejected(self):
        path = self._write("[danger]\nx = 1\n")
        with self.assertRaises(ConfigError):
            load_config(path)

    def test_wrong_type_is_rejected(self):
        path = self._write("[general]\nmax_rounds = \"three\"\n")
        with self.assertRaises(ConfigError):
            load_config(path)

    def test_invalid_toml_is_rejected(self):
        path = self._write("[general\nmode = auto\n")
        with self.assertRaises(ConfigError):
            load_config(path)

    def test_missing_explicit_file_is_an_error(self):
        with self.assertRaises(ConfigError):
            load_config("/nonexistent/aptai.toml")

    def test_webhook_must_be_a_url(self):
        path = self._write("[notify.mattermost]\nwebhook_url = \"; curl evil.example.com\"\n")
        with self.assertRaises(ConfigError):
            load_config(path)


class TestValidate(unittest.TestCase):
    def test_rejects_unknown_mode(self):
        config = Config()
        config.general.mode = "yolo"
        with self.assertRaises(ConfigError):
            validate(config)

    def test_rejects_plaintext_api_endpoint(self):
        config = Config()
        config.llm.base_url = "http://api.anthropic.com"
        with self.assertRaises(ConfigError):
            validate(config)

    def test_rejects_absurd_round_count(self):
        config = Config()
        config.general.max_rounds = 500
        with self.assertRaises(ConfigError):
            validate(config)

    def test_rejects_unknown_effort(self):
        config = Config()
        config.llm.effort = "ludicrous"
        with self.assertRaises(ConfigError):
            validate(config)

    def test_defaults_validate(self):
        validate(Config())

    def test_secrets_are_masked_in_the_dump(self):
        config = Config()
        config.notify.slack.webhook_url = "https://hooks.slack.com/services/A/B/C"
        dumped = config.to_dict()
        self.assertEqual("[set]", dumped["notify"]["slack"]["webhook_url"])


class TestResolveSecret(unittest.TestCase):
    def test_environment_wins(self):
        os.environ["APTAI_TEST_SECRET"] = "from-env"
        self.addCleanup(os.environ.pop, "APTAI_TEST_SECRET", None)
        self.assertEqual("from-env", resolve_secret("inline", "", "APTAI_TEST_SECRET"))

    def test_refuses_a_world_readable_file(self):
        handle = tempfile.NamedTemporaryFile("w", delete=False)
        handle.write("secret")
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        os.chmod(handle.name, 0o644)
        with self.assertRaises(ConfigError):
            resolve_secret("", handle.name)

    def test_reads_a_locked_down_file(self):
        handle = tempfile.NamedTemporaryFile("w", delete=False)
        handle.write("  secret\n")
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        os.chmod(handle.name, 0o600)
        self.assertEqual("secret", resolve_secret("", handle.name))

    def test_missing_everything_returns_empty(self):
        self.assertEqual("", resolve_secret("", "/nonexistent/key", "APTAI_NOT_SET_ANYWHERE"))


if __name__ == "__main__":
    unittest.main()


class TestNewLimits(unittest.TestCase):
    def test_max_new_installs_must_be_positive(self):
        config = Config()
        config.policy.max_new_installs = 0
        with self.assertRaises(ConfigError):
            validate(config)

    def test_payload_cap_must_be_sane(self):
        for value in (0, -1, 10, 10_000_000):
            with self.subTest(value=value):
                config = Config()
                config.privacy.max_payload_chars = value
                with self.assertRaises(ConfigError):
                    validate(config)

    def test_dpkg_log_lines_may_be_zero_but_not_negative(self):
        config = Config()
        config.privacy.dpkg_log_lines = 0
        validate(config)
        config.privacy.dpkg_log_lines = -1
        with self.assertRaises(ConfigError):
            validate(config)


class TestCommandLineOverrides(unittest.TestCase):
    """A command line flag must not be able to walk past a validated limit."""

    def test_max_rounds_is_validated(self):
        from aptai.cli import build_parser, _apply_overrides

        args = build_parser().parse_args(["run", "--max-rounds", "500"])
        config = Config()
        with self.assertRaises(ConfigError):
            _apply_overrides(config, args)

    def test_a_sane_override_is_applied(self):
        from aptai.cli import build_parser, _apply_overrides

        args = build_parser().parse_args(["run", "--max-rounds", "1", "--mode", "suggest"])
        config = Config()
        _apply_overrides(config, args)
        self.assertEqual(1, config.general.max_rounds)
        self.assertEqual("suggest", config.general.mode)

    def test_dry_run_flag(self):
        from aptai.cli import build_parser, _apply_overrides

        args = build_parser().parse_args(["run", "--dry-run"])
        config = Config()
        _apply_overrides(config, args)
        self.assertTrue(config.general.dry_run)


class TestCliEntryPoint(unittest.TestCase):
    """A bad override must report itself the way a bad config file does."""

    def test_invalid_max_rounds_exits_cleanly(self):
        import io
        import contextlib
        from aptai.cli import main

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = main(["--config", "config/aptai.toml", "run", "--max-rounds", "500"])
        self.assertEqual(2, code)
        self.assertIn("max_rounds", stderr.getvalue())

    def test_version_is_reported(self):
        import io
        import contextlib
        from aptai.cli import main

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), self.assertRaises(SystemExit) as ctx:
            main(["--version"])
        self.assertEqual(0, ctx.exception.code)
        self.assertIn("aptai", stdout.getvalue())
