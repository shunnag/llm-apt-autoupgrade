"""The second safety layer: apt's own simulation is inspected before executing."""

from __future__ import annotations

import os
import tempfile
import unittest

from aptai import aptcmd
from aptai.executor import (
    Executor,
    _atomic_write,
    _comment_out_uri,
    _key_mentioned,
    _purge_directory,
    _uri_host,
)
from aptai.policy import Policy
from tests.helpers import KERNEL, make_config, make_facts


SUMMARY = "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"


def sim(body: str, summary: str = SUMMARY):
    """Parse a simulation fragment, with apt's always-present summary line."""
    return aptcmd.parse_simulation(body + summary)


class TestSimulationGate(unittest.TestCase):
    def setUp(self) -> None:
        self.config = make_config()
        self.facts = make_facts()
        self.executor = Executor(self.config, Policy(self.config, self.facts), dry_run=True)

    def test_refuses_a_plan_that_removes_a_protected_package(self):
        problem = self.executor._review_simulation(
            sim("Remv nginx [1]\nRemv libc6 [2]\n"), removal_limit=100
        )
        self.assertIsNotNone(problem)
        self.assertIn("libc6", problem)

    def test_refuses_a_plan_that_removes_the_running_kernel(self):
        problem = self.executor._review_simulation(
            sim(f"Remv linux-image-{KERNEL} [1]\n"), removal_limit=100
        )
        self.assertIn("running kernel", problem or "")

    def test_purged_packages_count_as_removals(self):
        problem = self.executor._review_simulation(sim("Purg libc6 [1]\n"), removal_limit=100)
        self.assertIn("libc6", problem or "")

    def test_refuses_a_plan_over_the_removal_ceiling(self):
        body = "".join(f"Remv pkg{i} [1]\n" for i in range(12))
        problem = self.executor._review_simulation(sim(body), removal_limit=10)
        self.assertIn("over the configured limit", problem or "")

    def test_accepts_a_plan_within_the_ceiling(self):
        self.assertIsNone(
            self.executor._review_simulation(
                sim("Remv nginx [1]\nInst curl (2 x [amd64])\n"), removal_limit=10
            )
        )

    def test_refuses_downgrades_unless_allowed(self):
        parsed = sim("The following packages will be DOWNGRADED:\n  libfoo1\n")
        self.assertIn("downgrades", self.executor._review_simulation(parsed, removal_limit=10) or "")
        self.config.policy.allow_downgrade = True
        self.assertIsNone(self.executor._review_simulation(parsed, removal_limit=10))

    def test_unlimited_ceiling_still_protects_essential_packages(self):
        self.assertIsNotNone(
            self.executor._review_simulation(sim("Remv bash [1]\n"), removal_limit=-1)
        )

    def test_refuses_an_unparseable_simulation(self):
        # No summary line means apt's plan was not understood; an unknown plan
        # must never be executed.
        problem = self.executor._review_simulation(
            aptcmd.parse_simulation("Reading package lists...\n"), removal_limit=10
        )
        self.assertIn("could not be parsed", problem or "")

    def test_refuses_a_plan_over_the_new_install_ceiling(self):
        body = "".join(f"Inst pkg{i} (1 x [amd64])\n" for i in range(60))
        problem = self.executor._review_simulation(sim(body), removal_limit=10, install_limit=50)
        self.assertIn("installs 60 new packages", problem or "")

    def test_no_install_ceiling_by_default(self):
        body = "".join(f"Inst pkg{i} (1 x [amd64])\n" for i in range(200))
        self.assertIsNone(self.executor._review_simulation(sim(body), removal_limit=10))

    def test_fails_closed_when_the_dpkg_database_is_unreadable(self):
        from aptai.pkgfacts import PackageFacts

        broken = Executor(self.config, Policy(self.config, PackageFacts()), dry_run=True)
        problem = broken._review_simulation(sim("Remv some-random-package [1]\n"), removal_limit=100)
        self.assertIn("dpkg database could not be read", problem or "")


class TestKeyMention(unittest.TestCase):
    def test_key_must_appear_in_apt_own_error(self):
        error = (
            "W: GPG error: https://packages.example.com stable InRelease: The following "
            "signatures couldn't be verified because the public key is not available: "
            "NO_PUBKEY 648ACFD622F3D138"
        )
        self.assertTrue(_key_mentioned("648ACFD622F3D138", error))
        self.assertTrue(_key_mentioned("0x22F3D138", error))
        self.assertFalse(_key_mentioned("DEADBEEFDEADBEEF", error))
        self.assertFalse(_key_mentioned("648ACFD622F3D138", ""))

    def test_short_ids_are_refused(self):
        self.assertFalse(_key_mentioned("ABC", "NO_PUBKEY ABC"))


class TestUriHost(unittest.TestCase):
    def test_extracts_the_host(self):
        self.assertEqual("packages.example.com",
                         _uri_host("https://packages.example.com/debian"))
        self.assertEqual("packages.example.com",
                         _uri_host("https://packages.example.com:8443/debian"))
        self.assertEqual("", _uri_host("not-a-uri"))


class TestCommentOutUri(unittest.TestCase):
    def test_one_line_format(self):
        content = (
            "deb http://archive.ubuntu.com/ubuntu noble main\n"
            "deb https://packages.example.com/debian stable main\n"
            "# deb https://packages.example.com/debian stable contrib\n"
        )
        updated, changed = _comment_out_uri(content, "https://packages.example.com/debian")
        self.assertTrue(changed)
        self.assertIn("# deb https://packages.example.com/debian stable main", updated)
        self.assertIn("deb http://archive.ubuntu.com/ubuntu noble main", updated)
        self.assertNotIn("## deb", updated)

    def test_deb822_format(self):
        content = (
            "Types: deb\n"
            "URIs: https://archive.ubuntu.com/ubuntu\n"
            "Suites: noble\n"
            "Components: main\n"
            "\n"
            "Types: deb\n"
            "URIs: https://packages.example.com/debian\n"
            "Suites: stable\n"
            "Components: main\n"
        )
        updated, changed = _comment_out_uri(content, "https://packages.example.com/debian")
        self.assertTrue(changed)
        self.assertIn("# URIs: https://packages.example.com/debian", updated)
        self.assertIn("URIs: https://archive.ubuntu.com/ubuntu\n", updated)

    def test_no_match_reports_no_change(self):
        updated, changed = _comment_out_uri("deb http://a/b c d\n", "https://other/repo")
        self.assertFalse(changed)
        self.assertEqual("deb http://a/b c d\n", updated)


class TestPurgeDirectory(unittest.TestCase):
    def test_deletes_only_files_inside_the_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            lists = os.path.join(tmp, "lists")
            os.makedirs(os.path.join(lists, "partial"))
            outside = os.path.join(tmp, "outside.txt")
            with open(outside, "w", encoding="utf-8") as handle:
                handle.write("keep me")
            for name in ("a_InRelease", "b_Packages", "lock"):
                with open(os.path.join(lists, name), "w", encoding="utf-8") as handle:
                    handle.write("x")
            os.symlink(outside, os.path.join(lists, "escape"))
            count, problem = _purge_directory(lists, dry_run=False)
            self.assertIsNone(problem)
            self.assertEqual(2, count)
            self.assertTrue(os.path.exists(outside), "a symlink must not be followed out")
            self.assertTrue(os.path.exists(os.path.join(lists, "lock")))
            self.assertTrue(os.path.isdir(os.path.join(lists, "partial")))

    def test_dry_run_deletes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            lists = os.path.join(tmp, "lists")
            os.makedirs(lists)
            path = os.path.join(lists, "a_InRelease")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("x")
            count, problem = _purge_directory(lists, dry_run=True)
            self.assertIsNone(problem)
            self.assertEqual(1, count)
            self.assertTrue(os.path.exists(path))

    def test_refuses_a_symlinked_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            real = os.path.join(tmp, "real")
            os.makedirs(real)
            link = os.path.join(tmp, "link")
            os.symlink(real, link)
            count, problem = _purge_directory(link, dry_run=False)
            self.assertEqual(0, count)
            self.assertIn("symlink", problem or "")


class TestAtomicWrite(unittest.TestCase):
    def test_preserves_mode_and_replaces_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "x.list")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("old\n")
            os.chmod(path, 0o600)
            _atomic_write(path, "new\n")
            with open(path, encoding="utf-8") as handle:
                self.assertEqual("new\n", handle.read())
            self.assertEqual(0o600, os.stat(path).st_mode & 0o777)
            self.assertFalse(os.path.exists(path + ".aptai.tmp"))


if __name__ == "__main__":
    unittest.main()


class TestPartialUpdateDetection(unittest.TestCase):
    """apt-get update exits 0 even when a repository was not refreshed."""

    def test_detects_failed_fetch(self):
        from aptai.executor import partial_update_failures

        text = (
            "Hit:1 http://archive.ubuntu.com/ubuntu noble InRelease\n"
            "Err:2 https://packages.example.com/debian stable InRelease\n"
            "  404  Not Found\n"
            "W: Failed to fetch https://packages.example.com/debian/dists/stable/InRelease\n"
            "W: Some index files failed to download. They have been ignored, or old ones used instead.\n"
        )
        failures = partial_update_failures(text)
        self.assertTrue(any(f.startswith("Err:") for f in failures))
        self.assertTrue(any("Some index files failed" in f for f in failures))

    def test_detects_gpg_error(self):
        from aptai.executor import partial_update_failures

        text = "W: GPG error: https://packages.example.com stable InRelease: NO_PUBKEY 648ACFD622F3D138\n"
        self.assertEqual(1, len(partial_update_failures(text)))

    def test_a_clean_update_reports_nothing(self):
        from aptai.executor import partial_update_failures

        text = (
            "Hit:1 http://archive.ubuntu.com/ubuntu noble InRelease\n"
            "Get:2 http://archive.ubuntu.com/ubuntu noble-updates InRelease [126 kB]\n"
            "Fetched 126 kB in 1s (126 kB/s)\n"
            "Reading package lists...\n"
        )
        self.assertEqual([], partial_update_failures(text))


class TestSourceHostGuard(unittest.TestCase):
    """Disabling a repository requires apt to have complained about that host."""

    def test_a_prefix_does_not_satisfy_the_guard(self):
        from aptai.executor import _hosts_in, _uri_host

        error = "Err:5 https://packages.example.com/debian stable InRelease\n  404  Not Found"
        self.assertIn(_uri_host("https://packages.example.com/debian"), _hosts_in(error))
        self.assertNotIn(_uri_host("https://packages.example.com.evil.test/x"), _hosts_in(error))
        self.assertNotIn(_uri_host("https://archive.ubuntu.com/ubuntu"), _hosts_in(error))

    def test_userinfo_cannot_impersonate_a_host(self):
        from aptai.executor import _uri_host

        self.assertEqual("", _uri_host("https://packages.example.com@evil.test/debian"))

    def test_non_http_schemes_are_rejected(self):
        from aptai.executor import _uri_host

        for uri in ["file:///etc/passwd", "javascript:alert(1)", "", "not-a-uri"]:
            self.assertEqual("", _uri_host(uri))


class TestTabSeparatedSources(unittest.TestCase):
    def test_tab_separated_entry_is_commented_out(self):
        content = "deb\thttps://broken.example.com/apt\tstable\tmain\n"
        updated, changed = _comment_out_uri(content, "https://broken.example.com/apt")
        self.assertTrue(changed)
        self.assertTrue(updated.startswith("# deb"))

    def test_options_prefix_is_recognised(self):
        content = "deb[arch=amd64] https://broken.example.com/apt stable main\n"
        updated, changed = _comment_out_uri(content, "https://broken.example.com/apt")
        self.assertTrue(changed)
        self.assertTrue(updated.startswith("# deb["))

    def test_a_comment_is_not_commented_twice(self):
        content = "# deb https://broken.example.com/apt stable main\n"
        _, changed = _comment_out_uri(content, "https://broken.example.com/apt")
        self.assertFalse(changed)


class TestArgvRejectionEscalates(unittest.TestCase):
    """If a bad name ever reaches the executor, it must escalate, not crash."""

    def test_an_invalid_name_becomes_a_failed_result(self):
        from aptai.plan import Action, ActionKind

        config = make_config()
        executor = Executor(config, Policy(config, make_facts()), dry_run=True)
        # Bypasses the policy on purpose: this is the defence-in-depth path.
        bad = Action(kind=ActionKind.APT_INSTALL, reason="r", risk="low", packages=["ufw-"])
        result = executor.execute(bad)
        self.assertFalse(result.success)
        self.assertTrue(result.aborted_by_policy)
        self.assertIn("refused while building the command", result.message)

    def test_an_invalid_mark_target_becomes_a_failed_result(self):
        from aptai.plan import Action, ActionKind

        config = make_config()
        executor = Executor(config, Policy(config, make_facts()), dry_run=False)
        bad = Action(kind=ActionKind.APT_MARK, reason="r", risk="low",
                     mark="hold", packages=["linux-image."])
        result = executor.execute(bad)
        self.assertFalse(result.success)
        self.assertIn("refused while building the command", result.message)
