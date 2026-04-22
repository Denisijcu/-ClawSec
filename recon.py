#!/usr/bin/env python3
"""
ClawSec Recon Engine
Vertex Coders LLC — 2026
Runs nmap, whois, and subdomain enumeration.
Outputs structured JSON to /tmp/clawsec_results.json
"""

import argparse
import json
import subprocess
import sys
import socket
import datetime
import re
from pathlib import Path

OUTPUT_FILE = Path("/tmp/clawsec_results.json")

# ── Nmap scan profiles ─────────────────────────────────────────────────────────
SCAN_PROFILES = {
    "quick": ["-sV", "-T4", "--open", "-F"],               # top 100 ports, fast
    "full":  ["-sV", "-sC", "-T3", "--open", "-p-"],       # all 65535 ports
    "stealth": ["-sS", "-sV", "-T2", "--open", "-F"],      # SYN scan, slower
}


# ── Helpers ────────────────────────────────────────────────────────────────────

def run_cmd(cmd: list[str], timeout: int = 120) -> tuple[str, str, int]:
    """Run a shell command, return (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1
    except FileNotFoundError as e:
        return "", str(e), -1


def parse_nmap_output(raw: str) -> list[dict]:
    """
    Parse nmap -sV text output into list of port dicts.
    Each dict: { port, protocol, state, service, version }
    """
    ports = []
    port_re = re.compile(
        r"^(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)\s*(.*)$", re.MULTILINE
    )
    for m in port_re.finditer(raw):
        ports.append({
            "port": int(m.group(1)),
            "protocol": m.group(2),
            "state": m.group(3),
            "service": m.group(4),
            "version": m.group(5).strip(),
        })
    return ports


def run_nmap(target: str, scan_type: str) -> dict:
    """Execute nmap and return parsed results."""
    flags = SCAN_PROFILES.get(scan_type, SCAN_PROFILES["quick"])
    cmd = ["nmap"] + flags + [target]

    print(f"[recon] Running nmap ({scan_type}): {' '.join(cmd)}", file=sys.stderr)
    stdout, stderr, rc = run_cmd(cmd, timeout=180)

    if rc == -1 and "TIMEOUT" in stderr:
        return {"error": "nmap timed out", "raw": ""}

    if rc != 0 and not stdout:
        return {"error": stderr.strip(), "raw": ""}

    ports = parse_nmap_output(stdout)
    return {
        "raw": stdout,
        "ports": ports,
        "port_count": len(ports),
    }


def run_whois(target: str) -> dict:
    """Run whois and extract key fields."""
    print(f"[recon] Running whois on {target}", file=sys.stderr)
    stdout, stderr, rc = run_cmd(["whois", target], timeout=30)

    if rc != 0 or not stdout:
        # Fallback: try socket whois (port 43)
        return {"raw": stderr or "whois unavailable", "parsed": {}}

    # Extract common fields
    parsed = {}
    fields = {
        "Registrar": r"(?i)registrar:\s*(.+)",
        "Creation Date": r"(?i)creation date:\s*(.+)",
        "Expiry Date": r"(?i)(?:expiry|expiration) date:\s*(.+)",
        "Name Server": r"(?i)name server:\s*(.+)",
        "Registrant Org": r"(?i)registrant organization:\s*(.+)",
        "Country": r"(?i)registrant country:\s*(.+)",
    }
    for key, pattern in fields.items():
        match = re.search(pattern, stdout)
        if match:
            parsed[key] = match.group(1).strip()

    # Collect all nameservers
    ns_matches = re.findall(r"(?i)name server:\s*(.+)", stdout)
    if ns_matches:
        parsed["Name Servers"] = [ns.strip() for ns in ns_matches]

    return {"raw": stdout[:2000], "parsed": parsed}


def run_subdomain_enum(target: str) -> dict:
    """
    Basic subdomain enumeration using DNS bruteforce.
    Uses a small wordlist — no external tools required.
    """
    # Only run against domains, not IPs
    try:
        socket.inet_aton(target)
        return {"skipped": "Target is an IP address, subdomain enum not applicable"}
    except socket.error:
        pass

    print(f"[recon] Running subdomain enum on {target}", file=sys.stderr)

    wordlist = [
        "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
        "vpn", "remote", "portal", "app", "cdn", "static", "assets",
        "login", "auth", "dashboard", "beta", "secure", "mx", "smtp",
        "pop", "imap", "webmail", "ns1", "ns2", "git", "gitlab", "jenkins",
        "jira", "confluence", "docs", "support", "help", "shop", "store",
    ]

    found = []
    for sub in wordlist:
        fqdn = f"{sub}.{target}"
        try:
            ip = socket.gethostbyname(fqdn)
            found.append({"subdomain": fqdn, "ip": ip})
            print(f"[recon]   Found: {fqdn} → {ip}", file=sys.stderr)
        except socket.gaierror:
            pass

    return {
        "found": found,
        "count": len(found),
        "wordlist_size": len(wordlist),
    }


def risk_level(port: int, service: str, version: str) -> str:
    """Heuristic risk scoring for open ports."""
    high_risk_ports = {21, 23, 445, 3389, 5900, 1433, 3306, 5432, 27017, 6379}
    medium_risk_ports = {22, 80, 8080, 8443, 2049, 111}
    low_risk_ports = {443, 8000, 8888}

    version_lower = version.lower()
    # Outdated service versions → bump to critical
    if any(kw in version_lower for kw in ["2.4.4", "7.4", "5.5", "2003", "2008"]):
        return "Critical"

    if port in high_risk_ports:
        return "High"
    if port in medium_risk_ports:
        return "Medium"
    if port in low_risk_ports:
        return "Low"
    return "Info"


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="ClawSec Recon Engine")
    parser.add_argument("--target", required=True, help="IP or domain to scan")
    parser.add_argument(
        "--scan", default="quick",
        choices=["quick", "full", "stealth"],
        help="Scan profile"
    )
    parser.add_argument(
        "--modules", default="ports,whois",
        help="Comma-separated modules: ports,whois,subdomains"
    )
    args = parser.parse_args()

    modules = [m.strip() for m in args.modules.split(",")]
    results = {
        "meta": {
            "target": args.target,
            "scan_type": args.scan,
            "modules": modules,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "tool": "ClawSec by Vertex Coders LLC",
        },
        "nmap": {},
        "whois": {},
        "subdomains": {},
    }

    # Run requested modules
    if "ports" in modules:
        nmap_result = run_nmap(args.target, args.scan)
        # Enrich ports with risk levels
        if "ports" in nmap_result:
            for p in nmap_result["ports"]:
                p["risk"] = risk_level(p["port"], p["service"], p["version"])
        results["nmap"] = nmap_result

    if "whois" in modules:
        results["whois"] = run_whois(args.target)

    if "subdomains" in modules:
        results["subdomains"] = run_subdomain_enum(args.target)

    # Write output
    OUTPUT_FILE.write_text(json.dumps(results, indent=2))
    print(f"[recon] Results saved to {OUTPUT_FILE}", file=sys.stderr)

    # Print summary to stdout for OpenClaw to read
    port_count = results["nmap"].get("port_count", 0)
    sub_count = results["subdomains"].get("count", 0)
    print(f"DONE | ports={port_count} | subdomains={sub_count} | output={OUTPUT_FILE}")


if __name__ == "__main__":
    main()
