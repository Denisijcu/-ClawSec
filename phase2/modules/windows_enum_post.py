#!/usr/bin/env python3
"""
ClawSec Phase 2 — Windows Post-Exploitation Privilege Escalation Enum
Vertex Coders LLC

Generates a PowerShell ENUMERATION SCRIPT that the user pastes into the
shell on the compromised target. Then ingests the output and updates session.

For Windows targets where you got initial foothold (HTB Mediums típicamente).

Modes:
  - --gen-oneliner-cmd       cmd.exe one-liner (limited, no PS)
  - --gen-oneliner-ps        PowerShell rich enumeration (preferred)
  - --analyze <output_file>  Parse output and update session

This module does NOT run anything on the target. The user runs the
script in their shell, captures output, and pastes it back.
"""

from __future__ import annotations

import os
import sys
import json
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from phase2 import session as sess


# ── PowerShell one-liner ──────────────────────────────────────────────────────
# Usable from any shell that has PowerShell. Compact enough to paste.
WINDOWS_PS_ONELINER = r"""powershell -ep bypass -nop -c "
Write-Host '=== CLAWSEC WINDOWS ENUM ==='
Write-Host '[+] whoami / token'
whoami
whoami /priv
whoami /groups
Write-Host
Write-Host '[+] System info'
[System.Environment]::OSVersion
$env:COMPUTERNAME
$env:USERDOMAIN
hostname
Write-Host
Write-Host '[+] Current user privileges (interesting only)'
whoami /priv | Select-String -Pattern 'SeImpersonate|SeAssignPrimaryToken|SeBackup|SeRestore|SeDebug|SeTakeOwnership|SeLoadDriver|SeManageVolume'
Write-Host
Write-Host '[+] Local users'
Get-LocalUser 2>&1 | Format-Table Name,Enabled,LastLogon -AutoSize
Write-Host
Write-Host '[+] Local groups (admins)'
Get-LocalGroupMember -Group Administrators 2>&1 | Format-Table Name,PrincipalSource -AutoSize
Write-Host
Write-Host '[+] Network'
ipconfig /all | Select-String -Pattern 'IPv4|DNS|Gateway|Domain'
Write-Host
Write-Host '[+] Listening ports'
Get-NetTCPConnection -State Listen 2>&1 | Where-Object { $_.LocalAddress -ne '::' } | Format-Table LocalAddress,LocalPort,OwningProcess -AutoSize
Write-Host
Write-Host '[+] Running services with non-default paths or weak permissions'
Get-WmiObject win32_service | Where-Object { $_.PathName -notlike 'C:\Windows\*' -and $_.State -eq 'Running' } | Select-Object Name,DisplayName,PathName,StartMode | Format-List
Write-Host
Write-Host '[+] Unquoted service paths'
Get-WmiObject win32_service | Where-Object { $_.PathName -notmatch '\".*\"' -and $_.PathName -match ' ' -and $_.PathName -notlike 'C:\Windows*' } | Select-Object Name,PathName | Format-List
Write-Host
Write-Host '[+] Scheduled tasks (non-MS)'
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' -and $_.State -eq 'Ready' } | Select-Object TaskName,Author | Format-Table -AutoSize
Write-Host
Write-Host '[+] Installed software (recent)'
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* 2>$null | Select-Object DisplayName,DisplayVersion,Publisher | Where-Object { $_.DisplayName } | Format-Table -AutoSize | Out-String -Width 200
Write-Host
Write-Host '[+] AlwaysInstallElevated registry'
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>&1
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>&1
Write-Host
Write-Host '[+] Credentials hunting'
cmdkey /list 2>&1
Get-ChildItem -Path C:\Users\$env:USERNAME\AppData\Local\Microsoft\Credentials -Force -ErrorAction SilentlyContinue
Write-Host
Write-Host '[+] Looking for password files'
Get-ChildItem -Path C:\ -Recurse -Include *.config,*.ini,unattend*.xml,sysprep*.xml,Autounattend.xml,web.config -ErrorAction SilentlyContinue 2>&1 | Select-Object -First 30 | Select-Object FullName,Length
Write-Host
Write-Host '[+] PowerShell history'
$histPath = (Get-PSReadlineOption).HistorySavePath
if (Test-Path $histPath) {
    Get-Content $histPath -ErrorAction SilentlyContinue | Select-Object -Last 30
}
Write-Host
Write-Host '[+] User folders quick listing'
ls C:\Users\ -ErrorAction SilentlyContinue
Write-Host
Write-Host '[+] AD / Domain context (if joined)'
nltest /domain_trusts 2>&1
nltest /dclist:$env:USERDOMAIN 2>&1 | Select-Object -First 5
Write-Host
Write-Host '=== END CLAWSEC WINDOWS ENUM ==='
"
"""


# ── cmd.exe fallback (sin PowerShell) ─────────────────────────────────────────
WINDOWS_CMD_ONELINER = r"""cmd.exe /c "
echo === CLAWSEC WINDOWS CMD ENUM === &
echo [+] whoami ^& whoami /priv ^& whoami /groups &
whoami & whoami /priv & whoami /groups &
echo. &
echo [+] systeminfo ^(brief^) &
systeminfo | findstr /C:'OS Name' /C:'OS Version' /C:'System Type' /C:'Hotfix' &
echo. &
echo [+] ipconfig &
ipconfig /all &
echo. &
echo [+] netstat -ano ^(listening^) &
netstat -ano | findstr LISTENING &
echo. &
echo [+] tasklist /v &
tasklist /v &
echo. &
echo [+] service config snapshot &
sc query state= all | findstr SERVICE_NAME &
echo. &
echo [+] AlwaysInstallElevated &
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2^>nul &
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2^>nul &
echo. &
echo [+] cached credentials &
cmdkey /list &
echo. &
echo [+] users &
net users &
echo. &
echo [+] administrators &
net localgroup administrators &
echo. &
echo === END CLAWSEC WINDOWS CMD ENUM ===
"
"""


def parse_output(content: str) -> dict:
    """Heurística rápida sobre output Windows."""
    findings = {
        "current_user":     "",
        "computer":         "",
        "domain":           "",
        "interesting_priv": [],
        "admin_members":    [],
        "ports_listening":  [],
        "unquoted_services":[],
        "always_elevated":  False,
        "credentials_hint": [],
        "raw_chars":        len(content),
    }

    lines = content.splitlines()

    interesting_privs = ["SeImpersonate", "SeAssignPrimaryToken", "SeBackup",
                         "SeRestore", "SeDebug", "SeTakeOwnership", "SeLoadDriver"]

    for i, line in enumerate(lines):
        # current user from whoami
        if "\\" in line and i < 30 and not findings["current_user"]:
            stripped = line.strip()
            if stripped.count("\\") == 1 and not stripped.startswith("[") and " " not in stripped:
                findings["current_user"] = stripped

        for priv in interesting_privs:
            if priv in line and "Enabled" in line:
                findings["interesting_priv"].append(line.strip())

        if "AlwaysInstallElevated" in line and "0x1" in line:
            findings["always_elevated"] = True

        if "LISTENING" in line:
            findings["ports_listening"].append(line.strip())

        if "Target:" in line and ("LegacyGeneric" in line or "Domain:" in line):
            findings["credentials_hint"].append(line.strip())

    # Dedup
    findings["interesting_priv"] = list(set(findings["interesting_priv"]))
    return findings


def analyze(target: str, output_path_or_dash: str) -> dict:
    if output_path_or_dash == "-":
        content = sys.stdin.read()
    else:
        content = Path(output_path_or_dash).read_text(errors="replace")

    findings = parse_output(content)

    out_dir = Path(os.path.expanduser(f"~/.clawsec/sessions/{target}/windows_post"))
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "enum_output.txt").write_text(content)

    sess.add_enum_run(target, "windows_enum_post", "completed", {"findings": findings})

    return {
        "module":   "windows_enum_post",
        "target":   target,
        "findings": findings,
    }


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--gen-oneliner-ps",  action="store_true")
    ap.add_argument("--gen-oneliner-cmd", action="store_true")
    ap.add_argument("--analyze", default=None)
    args = ap.parse_args()

    if args.gen_oneliner_ps:
        print("# Paste this into target PowerShell, capture output, then:")
        print(f"#   python3 windows_enum_post.py {args.target} --analyze C:\\Windows\\Temp\\out.txt")
        print()
        print(WINDOWS_PS_ONELINER.strip())
        return 0

    if args.gen_oneliner_cmd:
        print("# Paste into target cmd.exe (no PowerShell available):")
        print()
        print(WINDOWS_CMD_ONELINER.strip())
        return 0

    if args.analyze:
        out = analyze(args.target, args.analyze)
        f = out["findings"]
        print(f"🦞 ClawSec Windows post-enum analysis for {args.target}")
        print("━" * 60)
        print(f"Current user:        {f['current_user'] or '?'}")
        print(f"AlwaysInstallElev:   {f['always_elevated']}")
        print(f"Interesting privs:   {len(f['interesting_priv'])}")
        for p in f["interesting_priv"][:5]:
            print(f"   {p}")
        print(f"Listening ports:     {len(f['ports_listening'])}")
        for p in f["ports_listening"][:5]:
            print(f"   {p}")
        print(f"Credential hints:    {len(f['credentials_hint'])}")
        for c in f["credentials_hint"][:5]:
            print(f"   {c}")
        print()
        print(f"Next: python3 phase2/exploit_advisor.py {args.target}")
        return 0

    ap.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
