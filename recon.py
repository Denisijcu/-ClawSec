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
import xml.etree.ElementTree as ET
from pathlib import Path

OUTPUT_FILE = Path("/tmp/clawsec_results.json")

# ── Nmap scan profiles (XML output added via -oX -) ───────────────────────────
SCAN_PROFILES = {
    "quick":   ["-sV", "-T4", "--open", "-F"],           # top 100 ports, fast
    "full":    ["-sV", "-sC", "-T3", "--open", "-p-"],   # all 65535 ports
    "stealth": ["-sS", "-sV", "-T2", "--open", "-F"],    # SYN scan, slower
}

# ── WHOIS servers per TLD (fallback when default whois fails) ─────────────────
WHOIS_SERVERS = {
    "com":  "whois.verisign-grs.com",
    "net":  "whois.verisign-grs.com",
    "org":  "whois.publicinterestregistry.org",
    "io":   "whois.nic.io",
    "dev":  "whois.nic.google",
    "app":  "whois.nic.google",
    "ai":   "whois.nic.ai",
    "co":   "whois.nic.co",
}

# ── Default subdomain wordlist (used when no --wordlist provided) ─────────────
DEFAULT_SUB_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "vpn", "remote", "portal", "app", "cdn", "static", "assets",
    "login", "auth", "dashboard", "beta", "secure", "mx", "smtp",
    "pop", "imap", "webmail", "ns1", "ns2", "git", "gitlab", "jenkins",
    "jira", "confluence", "docs", "support", "help", "shop", "store",
]


# ── Helpers ────────────────────────────────────────────────────────────────────

def utcnow_iso() -> str:
    """Timezone-aware UTC ISO timestamp (Python 3.12+ safe)."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


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


# ── Nmap: XML-based parsing (robust) ──────────────────────────────────────────

def parse_nmap_xml(xml_text: str) -> dict:
    """
    Parse nmap XML output. Returns:
        {
          "ports": [ {port, protocol, state, service, product, version,
                      extrainfo, cpe, scripts} ],
          "os": [ {name, accuracy} ],
          "hostnames": [str],
          "host_state": "up"/"down"/None,
        }
    """
    result = {"ports": [], "os": [], "hostnames": [], "host_state": None}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return result

    host = root.find("host")
    if host is None:
        return result

    status = host.find("status")
    if status is not None:
        result["host_state"] = status.get("state")

    for hn in host.findall("hostnames/hostname"):
        name = hn.get("name")
        if name:
            result["hostnames"].append(name)

    for port in host.findall("ports/port"):
        p = {
            "port": int(port.get("portid", 0)),
            "protocol": port.get("protocol", ""),
            "state": (port.find("state").get("state") if port.find("state") is not None else ""),
            "service": "",
            "product": "",
            "version": "",
            "extrainfo": "",
            "cpe": [],
            "scripts": [],
        }
        svc = port.find("service")
        if svc is not None:
            p["service"] = svc.get("name", "")
            p["product"] = svc.get("product", "")
            p["version"] = svc.get("version", "")
            p["extrainfo"] = svc.get("extrainfo", "")
            for cpe in svc.findall("cpe"):
                if cpe.text:
                    p["cpe"].append(cpe.text)
        for sc in port.findall("script"):
            p["scripts"].append({
                "id": sc.get("id", ""),
                "output": (sc.get("output", "") or "").strip(),
            })
        result["ports"].append(p)

    for osmatch in host.findall("os/osmatch"):
        result["os"].append({
            "name": osmatch.get("name", ""),
            "accuracy": int(osmatch.get("accuracy", 0)),
        })

    return result


def run_nmap(target: str, scan_type: str) -> dict:
    """Execute nmap with XML output and return parsed results."""
    flags = SCAN_PROFILES.get(scan_type, SCAN_PROFILES["quick"])
    # -oX - writes XML to stdout; we still want human-readable in stderr
    cmd = ["nmap"] + flags + ["-oX", "-", target]

    print(f"[recon] Running nmap ({scan_type}): {' '.join(cmd)}", file=sys.stderr)
    timeout = 600 if scan_type == "full" else 240
    stdout, stderr, rc = run_cmd(cmd, timeout=timeout)

    if rc == -1 and "TIMEOUT" in stderr:
        return {"error": "nmap timed out", "ports": [], "port_count": 0}

    if rc != 0 and not stdout:
        return {"error": stderr.strip(), "ports": [], "port_count": 0}

    parsed = parse_nmap_xml(stdout)
    return {
        "xml": stdout,
        "ports": parsed["ports"],
        "port_count": len(parsed["ports"]),
        "os": parsed["os"],
        "hostnames": parsed["hostnames"],
        "host_state": parsed["host_state"],
    }


# ── Whois with TLD-aware fallback ─────────────────────────────────────────────

def run_whois(target: str) -> dict:
    """Run whois and extract key fields. Falls back to TLD-specific server."""
    print(f"[recon] Running whois on {target}", file=sys.stderr)
    stdout, stderr, rc = run_cmd(["whois", target], timeout=30)

    # Detect malformed/empty responses and retry with explicit TLD server
    if rc != 0 or not stdout or "Malformed" in stdout or len(stdout) < 200:
        tld = target.rsplit(".", 1)[-1].lower() if "." in target else ""
        server = WHOIS_SERVERS.get(tld)
        if server:
            print(f"[recon]   retrying whois via {server}", file=sys.stderr)
            alt_out, alt_err, alt_rc = run_cmd(
                ["whois", "-h", server, target], timeout=30
            )
            if alt_rc == 0 and alt_out and len(alt_out) > len(stdout):
                stdout = alt_out

    if not stdout:
        return {"raw": stderr or "whois unavailable", "parsed": {}}

    parsed = {}
    fields = {
        "registrar":       r"(?im)^\s*registrar:\s*(.+)$",
        "creation_date":   r"(?im)^\s*creation date:\s*(.+)$",
        "expiry_date":     r"(?im)^\s*(?:registry expiry|expiry|expiration) date:\s*(.+)$",
        "registrant_org":  r"(?im)^\s*registrant organization:\s*(.+)$",
        "country":         r"(?im)^\s*registrant country:\s*(.+)$",
        "updated_date":    r"(?im)^\s*updated date:\s*(.+)$",
    }
    for key, pattern in fields.items():
        match = re.search(pattern, stdout)
        if match:
            parsed[key] = match.group(1).strip()

    ns_matches = re.findall(r"(?im)^\s*name server:\s*(\S+)", stdout)
    if ns_matches:
        parsed["name_servers"] = sorted({ns.strip().lower() for ns in ns_matches})

    return {"raw": stdout[:2000], "parsed": parsed}


# ── Subdomain enumeration ─────────────────────────────────────────────────────

def run_subdomain_enum(target: str, wordlist_path: str | None = None) -> dict:
    """
    Basic subdomain enumeration using DNS bruteforce.
    Uses DEFAULT_SUB_WORDLIST unless --wordlist provided.
    """
    # Only run against domains, not IPs
    try:
        socket.inet_aton(target)
        return {"skipped": "Target is an IP address, subdomain enum not applicable"}
    except socket.error:
        pass

    words = DEFAULT_SUB_WORDLIST
    if wordlist_path:
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                words = [w.strip() for w in f if w.strip() and not w.startswith("#")]
            print(f"[recon] Loaded {len(words)} words from {wordlist_path}", file=sys.stderr)
        except OSError as e:
            print(f"[recon] wordlist read failed ({e}); using default", file=sys.stderr)

    print(f"[recon] Running subdomain enum on {target} ({len(words)} words)", file=sys.stderr)

    found = []
    for sub in words:
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
        "wordlist_size": len(words),
    }


# ── Risk scoring (CPE + version-aware) ────────────────────────────────────────

# Ports that are almost always interesting / risky when exposed
HIGH_RISK_PORTS = {21, 23, 445, 3389, 5900, 1433, 3306, 5432, 27017, 6379, 139, 135}
MEDIUM_RISK_PORTS = {22, 80, 8080, 8443, 2049, 111, 25, 110, 143}
LOW_RISK_PORTS = {443, 8000, 8888}

# Known-bad version prefixes → Critical
# Keep conservative: only well-known EOL / CVE-heavy releases.
# Patterns accept ':' or whitespace before version, so they match both
# the service product string AND CPE URIs like cpe:/a:openbsd:openssh:6.6.1
CRITICAL_VERSION_PATTERNS = [
    (r"openssh[\s:]+(?:[0-5]\.|6\.[0-6])", "OpenSSH <= 6.6 (CVE-laden, EOL)"),
    (r"apache.*?(?:1\.|2\.0\.|2\.2\.|2\.4\.(?:[0-9]|1[0-9]|2[0-9])(?!\d))", "Apache httpd <= 2.4.29"),
    (r"nginx[/:\s]+(?:0\.|1\.[0-9]\.|1\.1[0-5]\.)", "nginx < 1.16"),
    (r"microsoft.*?iis[/:\s]+(?:[1-6]\.|7\.)", "IIS <= 7.x (EOL)"),
    (r"(?:windows[\s_])?server[\s_]200[0-8]", "Windows Server 2003/2008"),
    (r"vsftpd[\s:]+2\.3\.4", "vsftpd 2.3.4 (backdoor)"),
    (r"proftpd[\s:]+1\.3\.(?:3|5)", "ProFTPD 1.3.3/1.3.5 (RCE)"),
    (r"samba[\s:]+3\.", "Samba 3.x (EOL)"),
    (r"(?:mysql|mariadb)[\s:]+5\.[0-5]", "MySQL/MariaDB <= 5.5"),
    (r"php[/:\s]+5\.", "PHP 5.x (EOL)"),
]


def risk_level(port: int, service: str, version: str,
               cpe: list[str] | None = None, product: str = "") -> tuple[str, str]:
    """
    Heuristic risk scoring. Returns (level, reason).
    Levels: Critical / High / Medium / Low / Info
    """
    combined = f"{service} {product} {version} {' '.join(cpe or [])}".lower()

    for pattern, reason in CRITICAL_VERSION_PATTERNS:
        if re.search(pattern, combined):
            return "Critical", reason

    if port in HIGH_RISK_PORTS:
        return "High", f"Sensitive service port ({port})"
    if port in MEDIUM_RISK_PORTS:
        return "Medium", f"Commonly exposed service ({port})"
    if port in LOW_RISK_PORTS:
        return "Low", f"Standard service port ({port})"
    return "Info", "Non-standard / informational"


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
    parser.add_argument(
        "--wordlist", default=None,
        help="Custom subdomain wordlist (one per line)"
    )
    parser.add_argument(
        "--output", default=str(OUTPUT_FILE),
        help=f"Output JSON path (default: {OUTPUT_FILE})"
    )
    args = parser.parse_args()

    out_path = Path(args.output)
    modules = [m.strip() for m in args.modules.split(",") if m.strip()]
    results = {
        "meta": {
            "target": args.target,
            "scan_type": args.scan,
            "modules": modules,
            "timestamp": utcnow_iso(),
            "tool": "ClawSec by Vertex Coders LLC",
            "version": "0.2.0",
        },
        "nmap": {},
        "whois": {},
        "subdomains": {},
    }

    if "ports" in modules:
        nmap_result = run_nmap(args.target, args.scan)
        for p in nmap_result.get("ports", []):
            level, reason = risk_level(
                p["port"], p["service"], p["version"],
                p.get("cpe"), p.get("product", ""),
            )
            p["risk"] = level
            p["risk_reason"] = reason
        results["nmap"] = nmap_result

    if "whois" in modules:
        results["whois"] = run_whois(args.target)

    if "subdomains" in modules:
        results["subdomains"] = run_subdomain_enum(args.target, args.wordlist)

    out_path.write_text(json.dumps(results, indent=2))
    print(f"[recon] Results saved to {out_path}", file=sys.stderr)

    port_count = results["nmap"].get("port_count", 0)
    sub_count = results["subdomains"].get("count", 0)
    crit_count = sum(1 for p in results["nmap"].get("ports", []) if p.get("risk") == "Critical")
    high_count = sum(1 for p in results["nmap"].get("ports", []) if p.get("risk") == "High")
    print(
        f"DONE | ports={port_count} | critical={crit_count} | high={high_count} | "
        f"subdomains={sub_count} | output={out_path}"
    )


if __name__ == "__main__":
    main()
