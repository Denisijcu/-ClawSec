#!/usr/bin/env python3
"""
ClawSec Phase 2 — Linux Post-Exploitation Privilege Escalation Enum
Vertex Coders LLC

Generates a one-liner ENUMERATION SCRIPT that the user pastes into the
shell on the compromised target. Then ingests the output and asks the
LLM advisor for next-step privesc.

This module does NOT pivot or pwn anything itself. It only generates
the enum script and analyzes the output.

Usage:
  # 1. Generate one-liner to paste into the target shell
  python3 linux_enum_post.py <target> --gen-oneliner

  # 2. After running on target, paste output back
  python3 linux_enum_post.py <target> --analyze /path/to/output.txt
  # or read from stdin:
  cat output.txt | python3 linux_enum_post.py <target> --analyze -
"""

from __future__ import annotations

import os
import sys
import json
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from phase2 import session as sess


# ── One-liner enumeration script ──────────────────────────────────────────────
# Compacto, sin dependencias externas, solo binarios POSIX. ~150 líneas en bash.
LINUX_ONELINER = r"""bash -c '
echo "=== CLAWSEC LINUX ENUM ==="
echo "[+] whoami / id"
id
echo
echo "[+] kernel/distro"
uname -a
cat /etc/os-release 2>/dev/null | head -5
echo
echo "[+] sudo -l (no password prompt)"
sudo -n -l 2>&1 | head -30
echo
echo "[+] SUID binaries"
find / -perm -4000 -type f 2>/dev/null | head -50
echo
echo "[+] SGID binaries"
find / -perm -2000 -type f 2>/dev/null | head -30
echo
echo "[+] Capabilities (cap_setuid, etc)"
getcap -r / 2>/dev/null | head -30
echo
echo "[+] Cron jobs system-wide"
ls -la /etc/cron* 2>/dev/null | head -20
cat /etc/crontab 2>/dev/null
echo
echo "[+] Writable /etc files"
find /etc -writable -type f 2>/dev/null | head -20
echo
echo "[+] World-writable directories"
find / -perm -o+w -type d 2>/dev/null | grep -vE "^/proc|^/sys|^/run|^/tmp$|^/var/tmp$|^/dev" | head -20
echo
echo "[+] Listening ports (loopback included)"
ss -tlnp 2>/dev/null | head -20 || netstat -tlnp 2>/dev/null | head -20
echo
echo "[+] Services (systemd)"
systemctl list-units --type=service --state=running 2>/dev/null | head -20
echo
echo "[+] Running processes (root only)"
ps -eo user,pid,cmd 2>/dev/null | grep -E "^root" | head -20
echo
echo "[+] Mounted filesystems"
mount | head -20
echo
echo "[+] /etc/passwd users with shell"
grep -E "(/bin/bash|/bin/sh|/bin/zsh)$" /etc/passwd
echo
echo "[+] SSH keys / authorized_keys"
find / -name "id_rsa" -o -name "id_ed25519" -o -name "authorized_keys" 2>/dev/null | head -20
echo
echo "[+] env vars (filtered)"
env | grep -vE "^(PATH|LS_COLORS|LESSCLOSE|LESSOPEN|TERM)=" | head -20
echo
echo "[+] interesting files in /home, /opt, /var/www, /tmp, /root"
ls -la /root 2>/dev/null | head
ls -la /home/* 2>/dev/null | head -30
ls -la /opt 2>/dev/null
ls -la /var/www 2>/dev/null
echo
echo "[+] credentials in config files (best-effort)"
grep -rEl "(password|passwd|secret|api[_-]?key|token)" /etc /var/www /opt 2>/dev/null | head -20
echo
echo "[+] readable backup files"
find / \( -name "*.bak" -o -name "*.old" -o -name "*.orig" \) 2>/dev/null | head -20
echo
echo "[+] kernel exploits hints"
echo "Linux $(uname -r)"
echo
echo "=== END CLAWSEC LINUX ENUM ==="
'
"""


def gen_oneliner(target: str) -> str:
    """Return the one-liner for the user to paste into target shell."""
    return LINUX_ONELINER.replace("\n    ", "\n").strip()


def parse_output(content: str) -> dict:
    """Heurística rápida sobre el output del one-liner."""
    findings: dict = {
        "user":           "",
        "groups":         [],
        "kernel":         "",
        "distro":         "",
        "sudo_nopass":    [],
        "suid_unusual":   [],
        "capabilities":   [],
        "cron_writable":  [],
        "writable_etc":   [],
        "ssh_keys":       [],
        "env_secrets":    [],
        "raw_chars":      len(content),
    }

    lines = content.splitlines()

    # whoami / id
    for line in lines:
        if line.startswith("uid="):
            findings["user"] = line
        if line.lower().startswith("linux ") and "kernel" not in findings["distro"].lower():
            findings["kernel"] = line.strip()

    # SUID binarios "interesantes" (no estándar)
    KNOWN_SAFE_SUID = {
        "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/chsh",
        "/usr/bin/chfn", "/usr/bin/gpasswd", "/usr/bin/newgrp", "/usr/bin/mount",
        "/usr/bin/umount", "/usr/bin/pkexec", "/usr/lib/openssh/ssh-keysign",
        "/usr/lib/eject/dmcrypt-get-device", "/usr/bin/at",
        "/usr/lib/policykit-1/polkit-agent-helper-1",
    }
    in_suid = False
    for line in lines:
        if "[+] SUID binaries" in line:
            in_suid = True
            continue
        if line.startswith("[+] ") and in_suid:
            in_suid = False
        if in_suid and line.startswith("/"):
            if line.strip() not in KNOWN_SAFE_SUID:
                findings["suid_unusual"].append(line.strip())

    # sudo -l
    in_sudo = False
    for line in lines:
        if "sudo -l" in line:
            in_sudo = True
            continue
        if line.startswith("[+] ") and in_sudo:
            in_sudo = False
        if in_sudo and ("NOPASSWD" in line or "ALL" in line):
            findings["sudo_nopass"].append(line.strip())

    # Capabilities
    in_cap = False
    for line in lines:
        if "[+] Capabilities" in line:
            in_cap = True
            continue
        if line.startswith("[+] ") and in_cap:
            in_cap = False
        if in_cap and "cap_" in line:
            findings["capabilities"].append(line.strip())

    return findings


def analyze(target: str, output_path_or_dash: str) -> dict:
    if output_path_or_dash == "-":
        content = sys.stdin.read()
    else:
        content = Path(output_path_or_dash).read_text()

    findings = parse_output(content)

    # Save raw output to session
    out_dir = Path(os.path.expanduser(f"~/.clawsec/sessions/{target}/linux_post"))
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "enum_output.txt").write_text(content)

    # Update session
    sess.add_enum_run(target, "linux_enum_post", "completed", {"findings": findings})

    return {
        "module":   "linux_enum_post",
        "target":   target,
        "findings": findings,
    }


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--gen-oneliner", action="store_true",
                    help="Print the bash one-liner to paste into target shell")
    ap.add_argument("--analyze", default=None,
                    help="Path to output of one-liner (or '-' for stdin)")
    args = ap.parse_args()

    if args.gen_oneliner:
        print("# Paste this into the target shell, capture output, then run:")
        print(f"#   python3 linux_enum_post.py {args.target} --analyze /tmp/enum.txt\n")
        print(gen_oneliner(args.target))
        return 0

    if args.analyze:
        out = analyze(args.target, args.analyze)
        f = out["findings"]
        print(f"🦞 ClawSec Linux post-enum analysis for {args.target}")
        print("━" * 60)
        print(f"User:               {f['user']}")
        print(f"Kernel:             {f['kernel']}")
        print(f"sudo NOPASSWD:      {len(f['sudo_nopass'])} entries")
        for s in f["sudo_nopass"][:5]:
            print(f"   {s}")
        print(f"Unusual SUID:       {len(f['suid_unusual'])} binaries")
        for s in f["suid_unusual"][:10]:
            print(f"   {s}")
        print(f"Capabilities:       {len(f['capabilities'])}")
        for s in f["capabilities"][:5]:
            print(f"   {s}")
        print()
        print("Next: python3 phase2/exploit_advisor.py", args.target)
        return 0

    ap.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
