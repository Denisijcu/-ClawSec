#!/usr/bin/env python3
"""
Tests for ClawSec scope_guard.
Run: python3 -m pytest tests/ -v
  or: python3 tests/test_scope_guard.py
"""

import os
import sys
import unittest

# Make parent importable
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from scope_guard import validate  # noqa: E402


class ScopeGuardTests(unittest.TestCase):
    # ── Blocked by default ────────────────────────────────────────────────
    def test_rfc1918_192_blocked(self):
        ok, _ = validate("192.168.1.1")
        self.assertFalse(ok)

    def test_rfc1918_10_blocked(self):
        ok, _ = validate("10.0.0.1")
        self.assertFalse(ok)

    def test_loopback_blocked(self):
        ok, _ = validate("127.0.0.1")
        self.assertFalse(ok)

    def test_localhost_name_blocked(self):
        ok, _ = validate("localhost")
        self.assertFalse(ok)

    def test_aws_metadata_blocked(self):
        ok, _ = validate("169.254.169.254")
        self.assertFalse(ok)

    def test_gcp_metadata_name_blocked(self):
        ok, _ = validate("metadata.google.internal")
        self.assertFalse(ok)

    def test_dot_local_blocked(self):
        ok, _ = validate("router.local")
        self.assertFalse(ok)

    def test_invalid_format_blocked(self):
        ok, _ = validate("not a domain!!")
        self.assertFalse(ok)

    # ── Allowed ──────────────────────────────────────────────────────────
    def test_public_ip_allowed(self):
        ok, _ = validate("45.33.32.156")  # scanme.nmap.org
        self.assertTrue(ok)

    def test_public_domain_allowed(self):
        ok, _ = validate("example.com")
        self.assertTrue(ok)

    # ── --allow-lab behavior ─────────────────────────────────────────────
    def test_htb_blocked_by_default(self):
        ok, _ = validate("10.10.11.42")
        self.assertFalse(ok)

    def test_htb_allowed_with_allow_lab(self):
        ok, reason = validate("10.10.11.42", allow_lab=True)
        self.assertTrue(ok, reason)

    def test_htb_enterprise_allowed_with_allow_lab(self):
        ok, _ = validate("10.129.1.5", allow_lab=True)
        self.assertTrue(ok)

    def test_loopback_still_blocked_with_allow_lab(self):
        ok, _ = validate("127.0.0.1", allow_lab=True)
        self.assertFalse(ok)

    def test_aws_metadata_still_blocked_with_allow_lab(self):
        ok, _ = validate("169.254.169.254", allow_lab=True)
        self.assertFalse(ok)

    def test_rfc1918_192_still_blocked_with_allow_lab(self):
        # --allow-lab only opens HTB/Offsec ranges, not arbitrary LAN
        ok, _ = validate("192.168.1.1", allow_lab=True)
        self.assertFalse(ok)

    # ── --allowlist behavior ─────────────────────────────────────────────
    def test_allowlist_opens_private_ip(self):
        ok, _ = validate("192.168.50.10", allowlist={"192.168.50.10"})
        self.assertTrue(ok)

    def test_allowlist_does_not_open_metadata(self):
        ok, _ = validate("169.254.169.254", allowlist={"169.254.169.254"})
        self.assertFalse(ok)

    def test_allowlist_opens_domain(self):
        ok, _ = validate("internal.example.com", allowlist={"internal.example.com"})
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main(verbosity=2)
