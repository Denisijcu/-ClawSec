#!/usr/bin/env python3
"""
ClawSec Scope Guard
Vertex Coders LLC — 2026
Validates a target before any recon is executed.
Returns ALLOWED or BLOCKED to stdout.
"""

import sys
import ipaddress
import socket
import re

# ── Blocked IP ranges (RFC 1918 + special) ────────────────────────────────────
BLOCKED_NETWORKS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",       # loopback
    "169.254.0.0/16",    # link-local
    "0.0.0.0/8",
    "255.255.255.255/32",
    "224.0.0.0/4",       # multicast
]

# ── Blocked hostnames ──────────────────────────────────────────────────────────
BLOCKED_HOSTNAMES = [
    "localhost",
    "broadcasthost",
]

# ── Blocked TLDs (cloud metadata endpoints, etc.) ─────────────────────────────
BLOCKED_PATTERNS = [
    r"169\.254\.169\.254",     # AWS/GCP/Azure metadata
    r"metadata\.google\.internal",
    r"\.internal$",
    r"\.local$",
]


def is_valid_target(target: str) -> bool:
    """Basic format validation — must be IP or domain."""
    # IP check
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    # Domain check (simple)
    domain_re = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    return bool(domain_re.match(target))


def resolve_to_ip(target: str) -> str | None:
    """Try to resolve domain to IP. Returns None on failure."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def check_blocked_network(ip_str: str) -> bool:
    """Returns True if IP falls inside a blocked network."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for net in BLOCKED_NETWORKS:
            if ip in ipaddress.ip_network(net):
                return True
    except ValueError:
        pass
    return False


def check_blocked_patterns(target: str) -> bool:
    """Returns True if target matches any blocked regex pattern."""
    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, target, re.IGNORECASE):
            return True
    return False


def check_blocked_hostname(target: str) -> bool:
    return target.lower() in BLOCKED_HOSTNAMES


def validate(target: str) -> tuple[bool, str]:
    """
    Main validation logic.
    Returns (allowed: bool, reason: str)
    """
    target = target.strip().lower()

    # 1. Format check
    if not is_valid_target(target):
        return False, f"Invalid target format: '{target}'"

    # 2. Hostname blocklist
    if check_blocked_hostname(target):
        return False, f"Hostname '{target}' is blocked"

    # 3. Regex patterns
    if check_blocked_patterns(target):
        return False, f"Target '{target}' matches a blocked pattern"

    # 4. Direct IP check
    try:
        ipaddress.ip_address(target)
        if check_blocked_network(target):
            return False, f"IP '{target}' is in a blocked private/reserved range"
        # NOTE: HTB VPN IPs (10.10.x.x) are in RFC1918 — users must disable
        # scope guard or add to allowlist for HTB targets. See README.
        return True, "IP is routable and not in blocked range"
    except ValueError:
        pass

    # 5. Domain → resolve → check resolved IP
    resolved = resolve_to_ip(target)
    if resolved is None:
        # Can't resolve — warn but don't block (offline targets, internal DNS)
        return True, f"Domain '{target}' could not be resolved — proceeding with caution"

    if check_blocked_network(resolved):
        return False, (
            f"Domain '{target}' resolves to '{resolved}' which is in a blocked range"
        )

    return True, f"Domain '{target}' resolves to '{resolved}' — allowed"


def main():
    if len(sys.argv) < 2:
        print("BLOCKED")
        print("Usage: scope_guard.py <target>", file=sys.stderr)
        sys.exit(1)

    target = sys.argv[1]
    allowed, reason = validate(target)

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
