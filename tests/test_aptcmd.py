"""apt-get argv construction and simulation parsing."""

from __future__ import annotations

import unittest

from aptai.aptcmd import (
    DPKG_OPTIONS,
    apt_mark_argv,
    apt_packages_argv,
    apt_update_argv,
    disk_space,
    parse_simulation,
)

FULL_UPGRADE_SIM = """\
NOTE: This is only a simulation!
      apt-get needs root privileges for real execution.
Reading package lists...
Building dependency tree...
Reading state information...
Calculating upgrade...
The following packages will be REMOVED:
  linux-image-6.8.0-31-generic linux-modules-6.8.0-31-generic
The following NEW packages will be installed:
  linux-image-6.8.0-45-generic
The following packages will be upgraded:
  base-files libc6 libc-bin
3 upgraded, 1 newly installed, 2 to remove and 0 not upgraded.
Inst base-files [12ubuntu4.6] (12ubuntu4.7 Ubuntu:24.04/noble-updates [amd64])
Remv linux-image-6.8.0-31-generic [6.8.0-31.31]
Remv linux-modules-6.8.0-31-generic [6.8.0-31.31]
Conf base-files (12ubuntu4.7 Ubuntu:24.04/noble-updates [amd64])
"""

HELD_BACK_SIM = """\
Reading package lists...
The following packages have been kept back:
  linux-generic linux-headers-generic
0 upgraded, 0 newly installed, 0 to remove and 2 not upgraded.
"""


class TestParseSimulation(unittest.TestCase):
    def test_parses_a_real_full_upgrade_plan(self):
        sim = parse_simulation(FULL_UPGRADE_SIM)
        self.assertEqual(
            ["linux-image-6.8.0-31-generic", "linux-modules-6.8.0-31-generic"], sim.removals
        )
        self.assertIn("linux-image-6.8.0-45-generic", sim.new_installs)
        self.assertEqual(["base-files", "libc6", "libc-bin"], sim.upgrades)
        self.assertEqual(2, sim.removal_count)
        self.assertTrue(sim.parsed_summary)

    def test_parses_held_back_packages(self):
        sim = parse_simulation(HELD_BACK_SIM)
        self.assertEqual(["linux-generic", "linux-headers-generic"], sim.held_back)
        self.assertEqual(0, sim.removal_count)

    def test_remv_lines_alone_are_enough(self):
        sim = parse_simulation("Remv foo [1]\nRemv bar [2]\n")
        self.assertEqual(["foo", "bar"], sim.removals)

    def test_purge_asterisk_is_stripped(self):
        sim = parse_simulation("The following packages will be REMOVED:\n  nginx* curl*\n")
        self.assertEqual(["nginx", "curl"], sim.removals)

    def test_empty_output(self):
        sim = parse_simulation("")
        self.assertEqual([], sim.removals)
        self.assertFalse(sim.parsed_summary)

    def test_section_ends_at_a_blank_line(self):
        sim = parse_simulation(
            "The following packages will be REMOVED:\n  a b\n\nSomething else\n  c d\n"
        )
        self.assertEqual(["a", "b"], sim.removals)


class TestArgv(unittest.TestCase):
    def test_simulation_flag_and_dpkg_options(self):
        argv = apt_packages_argv("full-upgrade", simulate=True)
        self.assertIn("-s", argv)
        self.assertNotIn("-y", argv)
        for option in DPKG_OPTIONS:
            self.assertIn(option, argv)
        self.assertEqual("full-upgrade", argv[-1])

    def test_real_run_is_non_interactive(self):
        argv = apt_packages_argv("install", ["nginx"])
        self.assertIn("-y", argv)
        self.assertIn("Dpkg::Options::=--force-confold", argv)
        self.assertEqual(["install", "nginx"], argv[-2:])

    def test_option_like_package_names_are_refused(self):
        for name in ["--purge", "-y", "--allow-remove-essential"]:
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    apt_packages_argv("remove", [name])

    def test_apt_mark_rejects_unknown_subcommand(self):
        with self.assertRaises(ValueError):
            apt_mark_argv("delete-everything", ["nginx"])
        with self.assertRaises(ValueError):
            apt_mark_argv("hold", ["--force"])

    def test_apt_mark_builds_a_list(self):
        self.assertEqual(
            ["/usr/bin/apt-mark", "hold", "nginx", "curl"], apt_mark_argv("hold", ["nginx", "curl"])
        )

    def test_update_argv_is_minimal(self):
        argv = apt_update_argv()
        self.assertEqual("update", argv[-1])
        self.assertNotIn("Dpkg::Options::=--force-confold", argv)


class TestDiskSpace(unittest.TestCase):
    def test_reports_free_space_for_an_existing_path(self):
        space = disk_space("/")
        self.assertTrue(space.exists)
        self.assertGreater(space.total_mb, 0)

    def test_missing_path(self):
        self.assertFalse(disk_space("/nonexistent-path-for-aptai-tests").exists)


if __name__ == "__main__":
    unittest.main()
