#!/usr/bin/env python3
"""
ClawSec Scope Guard
Vertex Coders LLC — 2026
Validates a target before any recon is executed.
Returns ALLOWED or BLOCKED to stdout.

Usage:
    scope_guard.py <target>
    scope_guard.py --allow-lab 10.10.11.42   # allow HTB/lab RFC1918 on request
    scope_guard.py --allowlist ~/.clawsec/allowlist.txt <target>
"""

import argparse
import ipaddress
import os
import re
import socket
import sys

# ── Blocked IP ranges (RFC 1918 + special) ────────────────────────────────────
BLOCKED_NETWORKS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",        # loopback
    "169.254.0.0/16",     # link-local
    "0.0.0.0/8",
    "255.255.255.255/32",
    "224.0.0.0/4",        # multicast
]

# Always-deny, even with --allow-lab
ALWAYS_BLOCKED_NETWORKS = [
    "127.0.0.0/8",
    "169.254.0.0/16",
    "0.0.0.0/8",
    "255.255.255.255/32",
    "224.0.0.0/4",
]

BLOCKED_HOSTNAMES = [
    "localhost",
    "broadcasthost",
]

BLOCKED_PATTERNS = [
    r"169\.254\.169\.254",            # AWS/GCP/Azure metadata
    r"metadata\.google\.internal",
    r"\.internal$",
    r"\.local$",
]

# Well-known lab / CTF networks (HTB/TryHackMe/etc.) that --allow-lab permits
LAB_NETWORKS = [
    "10.10.0.0/16",       # HackTheBox VPN
    "10.129.0.0/16",      # HackTheBox Enterprise / newer machines
    "10.11.0.0/16",       # Offsec / OSCP labs
    "172.20.0.0/16",      # Vertex Coders internal lab (custom HTB-style boxes)
]


def is_valid_target(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    domain_re = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    return bool(domain_re.match(target))


def resolve_to_ip(target: str) -> str | None:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def ip_in_any(ip_str: str, nets: list[str]) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for net in nets:
        if ip in ipaddress.ip_network(net):
            return True
    return False


def check_blocked_patterns(target: str) -> bool:
    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, target, re.IGNORECASE):
            return True
    return False


def check_blocked_hostname(target: str) -> bool:
    return target.lower() in BLOCKED_HOSTNAMES


def load_allowlist(path: str | None) -> set[str]:
    """Load user allowlist file. Lines are exact targets (IP or domain).
    Comments (#) and blanks ignored."""
    if not path:
        return set()
    expanded = os.path.expanduser(path)
    if not os.path.exists(expanded):
        return set()
    entries: set[str] = set()
    with open(expanded, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                entries.add(line.lower())
    return entries


def validate(target: str, *, allow_lab: bool = False, allowlist: set[str] | None = None) -> tuple[bool, str]:
    """Returns (allowed, reason)."""
    target = target.strip().lower()
    allowlist = allowlist or set()

    # 0. Explicit user allowlist wins (still blocks truly dangerous things below)
    explicit = target in allowlist

    # 1. Format check
    if not is_valid_target(target):
        return False, f"Invalid target format: '{target}'"

    # 2. Hostname blocklist (hard stop, even with allowlist)
    if check_blocked_hostname(target):
        return False, f"Hostname '{target}' is always blocked"

    # 3. Metadata/internal patterns (hard stop)
    if check_blocked_patterns(target):
        return False, f"Target '{target}' matches a blocked metadata/internal pattern"

    # 4. Direct IP
    try:
        ipaddress.ip_address(target)
        is_ip = True
    except ValueError:
        is_ip = False

    def evaluate_ip(ip_str: str, label: str) -> tuple[bool, str]:
        if ip_in_any(ip_str, ALWAYS_BLOCKED_NETWORKS):
            return False, f"{label} '{ip_str}' is in an always-blocked range"
        if ip_in_any(ip_str, BLOCKED_NETWORKS):
            if explicit:
                return True, f"{label} '{ip_str}' private, but on user allowlist"
            if allow_lab and ip_in_any(ip_str, LAB_NETWORKS):
                return True, f"{label} '{ip_str}' is a recognized lab/CTF range (--allow-lab)"
            return False, f"{label} '{ip_str}' is in a blocked private/reserved range"
        return True, f"{label} '{ip_str}' is routable and not in blocked range"

    if is_ip:
        return evaluate_ip(target, "IP")

    # 5. Domain → resolve → check IP
    if explicit:
        return True, f"Domain '{target}' is on user allowlist"

    resolved = resolve_to_ip(target)
    if resolved is None:
        return True, f"Domain '{target}' could not be resolved — proceeding with caution"

    return evaluate_ip(resolved, f"Domain '{target}' resolves to")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="ClawSec Scope Guard")
    p.add_argument("target", help="IP or domain to validate")
    p.add_argument(
        "--allow-lab", action="store_true",
        help="Allow well-known lab/CTF RFC1918 ranges (HTB 10.10/10.129, Offsec 10.11)."
    )
    p.add_argument(
        "--allowlist", default=None,
        help="Path to user allowlist (one target per line). Overrides blocks except always-blocked ranges."
    )
    return p


def main():
    parser = build_parser()
    # Backwards-compat: still accept bare `scope_guard.py <target>` with no flags
    args = parser.parse_args()

    allowlist = load_allowlist(args.allowlist)
    allowed, reason = validate(args.target, allow_lab=args.allow_lab, allowlist=allowlist)

    if allowed:
        print("ALLOWED")
        print(f"[scope_guard] {reason}", file=sys.stderr)
        sys.exit(0)
    else:
        print("BLOCKED")
        print(f"[scope_guard] {reason}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
