#!/usr/bin/env python3
"""
Tests for ClawSec risk_level scoring.
Run: python3 tests/test_risk.py
"""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from recon import risk_level  # noqa: E402


class RiskLevelTests(unittest.TestCase):

    # ── Critical via known-bad versions ──────────────────────────────────
    def test_openssh_6_6_critical(self):
        level, _ = risk_level(
            22, "ssh", "6.6.1p1 Ubuntu 2ubuntu2.13",
            ["cpe:/a:openbsd:openssh:6.6.1p1"], "OpenSSH",
        )
        self.assertEqual(level, "Critical")

    def test_openssh_5_x_critical(self):
        level, _ = risk_level(22, "ssh", "5.3p1", [], "OpenSSH")
        self.assertEqual(level, "Critical")

    def test_openssh_modern_not_critical(self):
        # OpenSSH 9.x should NOT be flagged critical
        level, _ = risk_level(22, "ssh", "9.6p1", [], "OpenSSH")
        self.assertNotEqual(level, "Critical")

    def test_apache_2_4_7_critical(self):
        level, _ = risk_level(
            80, "http", "2.4.7",
            ["cpe:/a:apache:http_server:2.4.7"], "Apache httpd",
        )
        self.assertEqual(level, "Critical")

    def test_apache_2_4_29_critical(self):
        level, _ = risk_level(80, "http", "2.4.29", [], "Apache httpd")
        self.assertEqual(level, "Critical")

    def test_apache_modern_not_critical(self):
        # Apache 2.4.58 should NOT be Critical by version
        level, _ = risk_level(80, "http", "2.4.58", [], "Apache httpd")
        self.assertNotEqual(level, "Critical")

    def test_vsftpd_backdoor_critical(self):
        level, reason = risk_level(21, "ftp", "2.3.4", [], "vsftpd")
        self.assertEqual(level, "Critical")
        self.assertIn("backdoor", reason.lower())

    def test_php_5_critical(self):
        level, _ = risk_level(80, "http", "", ["cpe:/a:php:php:5.4.16"], "")
        self.assertEqual(level, "Critical")

    # ── Port-based fallback ─────────────────────────────────────────────
    def test_rdp_high(self):
        level, _ = risk_level(3389, "ms-wbt-server", "", [], "")
        self.assertEqual(level, "High")

    def test_https_low(self):
        level, _ = risk_level(443, "ssl/http", "", [], "")
        self.assertEqual(level, "Low")

    def test_weird_port_info(self):
        level, _ = risk_level(31337, "unknown", "", [], "")
        self.assertEqual(level, "Info")


if __name__ == "__main__":
    unittest.main(verbosity=2)
