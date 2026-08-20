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


class TestSimulationGate(unittest.TestCase):
    def setUp(self) -> None:
        self.config = make_config()
        self.facts = make_facts()
        self.executor = Executor(self.config, Policy(self.config, self.facts), dry_run=True)

    def test_refuses_a_plan_that_removes_a_protected_package(self):
        sim = aptcmd.parse_simulation("Remv nginx [1]\nRemv libc6 [2]\n")
        problem = self.executor._review_simulation(sim, removal_limit=100)
        self.assertIsNotNone(problem)
        self.assertIn("libc6", problem)

    def test_refuses_a_plan_that_removes_the_running_kernel(self):
        sim = aptcmd.parse_simulation(f"Remv linux-image-{KERNEL} [1]\n")
        problem = self.executor._review_simulation(sim, removal_limit=100)
        self.assertIn("running kernel", problem or "")

    def test_refuses_a_plan_over_the_removal_ceiling(self):
        sim = aptcmd.parse_simulation("".join(f"Remv pkg{i} [1]\n" for i in range(12)))
        problem = self.executor._review_simulation(sim, removal_limit=10)
        self.assertIn("over the configured limit", problem or "")

    def test_accepts_a_plan_within_the_ceiling(self):
        sim = aptcmd.parse_simulation("Remv nginx [1]\nInst curl (2 x [amd64])\n")
        self.assertIsNone(self.executor._review_simulation(sim, removal_limit=10))

    def test_refuses_downgrades_unless_allowed(self):
        sim = aptcmd.parse_simulation(
            "The following packages will be DOWNGRADED:\n  libfoo1\n"
        )
        self.assertIn("downgrades", self.executor._review_simulation(sim, removal_limit=10) or "")
        self.config.policy.allow_downgrade = True
        self.assertIsNone(self.executor._review_simulation(sim, removal_limit=10))

    def test_unlimited_ceiling_still_protects_essential_packages(self):
        sim = aptcmd.parse_simulation("Remv bash [1]\n")
        self.assertIsNotNone(self.executor._review_simulation(sim, removal_limit=-1))


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
