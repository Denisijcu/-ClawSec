#!/usr/bin/env python3
"""
ClawSec Phase 2 — SMB / Windows Enumeration
Vertex Coders LLC

Runs a battery of passive SMB checks and parses output into structured
session data. All commands here are READ-ONLY and considered safe in
authorized labs.

Tools used (all should be in Kali/Parrot by default):
  - nmap NSE smb scripts
  - smbclient -L
  - enum4linux-ng (preferred) or enum4linux
  - nbtscan
  - rpcclient
  - crackmapexec (cme) for share enumeration

Outputs:
  - Updates session.json (shares, users, OS info, etc.)
  - Writes raw outputs to ~/.clawsec/sessions/<target>/smb/
  - Returns dict summary
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# Allow running as standalone script from /opt/clawsec
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from phase2 import session as sess


def _which(*candidates: str) -> str | None:
    for c in candidates:
        path = shutil.which(c)
        if path:
            return path
    return None


def _run(cmd: list[str], timeout: int = 60) -> tuple[int, str]:
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, errors="replace"
        )
        return out.returncode, (out.stdout + out.stderr)
    except subprocess.TimeoutExpired:
        return -1, f"[timeout after {timeout}s]"
    except FileNotFoundError:
        return -2, f"[binary not found: {cmd[0]}]"
    except Exception as e:
        return -3, f"[error: {e}]"


def _save_raw(target: str, name: str, content: str) -> Path:
    out_dir = Path(os.path.expanduser(f"~/.clawsec/sessions/{target}/smb"))
    out_dir.mkdir(parents=True, exist_ok=True)
    fp = out_dir / f"{name}.txt"
    fp.write_text(content)
    return fp


# ── Probes ────────────────────────────────────────────────────────────────────

def probe_nmap_smb(target: str) -> dict:
    """nmap NSE: smb-os-discovery, smb-protocols, smb-security-mode, smb2-security-mode"""
    nmap = _which("nmap")
    if not nmap:
        return {"status": "error", "msg": "nmap not installed"}

    scripts = "smb-os-discovery,smb-protocols,smb-security-mode,smb2-security-mode,smb-enum-shares"
    code, out = _run(
        [nmap, "-Pn", "-p", "139,445", "--script", scripts, target],
        timeout=120,
    )
    _save_raw(target, "nmap_smb_scripts", out)

    # Parsea OS discovery
    os_info = {}
    for line in out.splitlines():
        m = re.match(r"\|\s+OS:\s*(.*)", line)
        if m:
            os_info["os"] = m.group(1).strip()
        m = re.match(r"\|\s+Computer name:\s*(.*)", line)
        if m:
            os_info["computer_name"] = m.group(1).strip()
        m = re.match(r"\|\s+Domain name:\s*(.*)", line)
        if m and m.group(1).strip():
            os_info["domain"] = m.group(1).strip()
        m = re.match(r"\|\s+NetBIOS computer name:\s*(.*)", line)
        if m:
            os_info["netbios"] = m.group(1).strip()

    # Parsea shares
    shares: list[dict] = []
    cur_share = None
    for line in out.splitlines():
        m = re.match(r"\|\s+(\\\\[^\s]+\\[^\s:]+):", line)
        if m:
            cur_share = {"share": m.group(1).split("\\")[-1], "access": "unknown"}
            shares.append(cur_share)
        if cur_share and "Anonymous access:" in line:
            cur_share["anonymous"] = line.split(":", 1)[1].strip()

    return {
        "status":   "ok" if code == 0 else "partial",
        "os_info":  os_info,
        "shares":   shares,
        "raw_path": "smb/nmap_smb_scripts.txt",
    }


def probe_smbclient_list(target: str) -> dict:
    """smbclient -L //target -N (anonymous list shares)"""
    sc = _which("smbclient")
    if not sc:
        return {"status": "error", "msg": "smbclient not installed"}

    code, out = _run([sc, "-L", f"//{target}", "-N", "--option=client min protocol=NT1"],
                     timeout=30)
    _save_raw(target, "smbclient_list", out)

    shares: list[dict] = []
    in_shares = False
    for line in out.splitlines():
        if "Sharename" in line and "Type" in line:
            in_shares = True
            continue
        if in_shares:
            if not line.strip() or "Server" in line or "Workgroup" in line:
                in_shares = False
                continue
            parts = line.split()
            if len(parts) >= 2:
                shares.append({"share": parts[0], "type": parts[1]})

    return {
        "status":   "ok" if code == 0 else "blocked",
        "shares":   shares,
        "anonymous_allowed": code == 0 and bool(shares),
        "raw_path": "smb/smbclient_list.txt",
    }


def probe_enum4linux(target: str) -> dict:
    """enum4linux-ng (preferred) or enum4linux."""
    bin_path = _which("enum4linux-ng", "enum4linux")
    if not bin_path:
        return {"status": "error", "msg": "enum4linux not installed (apt install enum4linux-ng)"}

    is_ng = "ng" in bin_path
    cmd = [bin_path, "-A", target] if is_ng else [bin_path, "-a", target]
    code, out = _run(cmd, timeout=240)
    _save_raw(target, "enum4linux", out)

    # Parsing minimal — extracción de usuarios y grupos
    users: list[str] = []
    groups: list[str] = []

    # enum4linux-ng JSON-ish format vs classic
    user_re = re.compile(r"user:\[([^\]]+)\]|index:\s*\d+\s+RID:\s*0x[0-9a-f]+\s+\(\d+\)\s+(\S+)")
    for m in user_re.finditer(out):
        u = m.group(1) or m.group(2)
        if u and u not in users:
            users.append(u)

    group_re = re.compile(r"group:\[([^\]]+)\]")
    for m in group_re.finditer(out):
        g = m.group(1)
        if g and g not in groups:
            groups.append(g)

    return {
        "status":   "ok" if code in (0, 1) else "error",
        "users":    users,
        "groups":   groups,
        "raw_path": "smb/enum4linux.txt",
    }


def probe_crackmapexec(target: str) -> dict:
    """cme smb target — quick OS / signing / shares anonymous."""
    cme = _which("crackmapexec", "netexec", "nxc")
    if not cme:
        return {"status": "skipped", "msg": "crackmapexec/netexec not installed"}

    summary = {}
    # 1. Info básica
    code, out = _run([cme, "smb", target], timeout=30)
    _save_raw(target, "cme_info", out)
    m = re.search(r"\(name:([^)]+)\) \(domain:([^)]+)\)", out)
    if m:
        summary["computer_name"] = m.group(1)
        summary["domain"]        = m.group(2)
    summary["signing"] = "enforced" if "signing:True" in out else (
                         "disabled" if "signing:False" in out else "unknown")

    # 2. Shares con null session
    code, out = _run([cme, "smb", target, "-u", "''", "-p", "''", "--shares"], timeout=30)
    _save_raw(target, "cme_shares_null", out)
    shares: list[dict] = []
    for line in out.splitlines():
        m = re.search(r"\s+(\S+)\s+(READ|WRITE|READ,WRITE|NO ACCESS)\s+", line)
        if m:
            shares.append({"share": m.group(1), "access": m.group(2)})

    summary["shares_null_session"] = shares
    return {"status": "ok", **summary}


# ── Orquestador ───────────────────────────────────────────────────────────────

def run(target: str, ports: list[dict] | None = None) -> dict:
    """Entrypoint: corre todas las probes SMB y actualiza la sesión."""
    print(f"[smb_enum] Starting SMB enumeration for {target}")

    results = {
        "module": "smb_enum",
        "target": target,
        "probes": {},
    }

    print(f"[smb_enum] (1/4) nmap NSE smb scripts...")
    results["probes"]["nmap_smb"] = probe_nmap_smb(target)

    print(f"[smb_enum] (2/4) smbclient -L (null session)...")
    results["probes"]["smbclient"] = probe_smbclient_list(target)

    print(f"[smb_enum] (3/4) crackmapexec / netexec...")
    results["probes"]["cme"] = probe_crackmapexec(target)

    print(f"[smb_enum] (4/4) enum4linux-ng (this is the slow one)...")
    results["probes"]["enum4linux"] = probe_enum4linux(target)

    # ── Update session ────────────────────────────────────────────────────────
    sess.add_enum_run(target, "smb_enum", "completed", results)

    # Shares de cualquier fuente
    all_shares: dict[str, str] = {}
    for src in ("nmap_smb", "smbclient", "cme"):
        for sh in results["probes"][src].get("shares", []) or results["probes"][src].get("shares_null_session", []):
            name = sh.get("share")
            access = sh.get("access") or sh.get("type") or "unknown"
            if name:
                all_shares[name] = access
    for share, access in all_shares.items():
        sess.add_share(target, share, access)

    # Users
    users = results["probes"]["enum4linux"].get("users", [])
    if users:
        sess.add_users(target, users)

    # Resumen
    summary = {
        "shares_found":    len(all_shares),
        "users_found":     len(users),
        "anonymous_smb":   results["probes"]["smbclient"].get("anonymous_allowed", False),
        "os_info":         results["probes"]["nmap_smb"].get("os_info", {}),
        "signing":         results["probes"]["cme"].get("signing", "unknown"),
    }
    results["summary"] = summary
    print(f"[smb_enum] ✅ Done. Shares: {summary['shares_found']} | "
          f"Users: {summary['users_found']} | "
          f"Anon SMB: {summary['anonymous_smb']} | "
          f"Signing: {summary['signing']}")
    return results


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("target", help="IP or hostname")
    args = p.parse_args()
    out = run(args.target)
    import json as _j
    print("\n--- RESULTS SUMMARY ---")
    print(_j.dumps(out["summary"], indent=2))
