#!/usr/bin/env python3
"""
ClawSec Phase 2 — Enumeration Dispatcher
Vertex Coders LLC

Reads phase 1 output (/tmp/clawsec_results.json or session phase1)
and decides which deeper enumeration modules to run.

Detected stacks → modules:
  smb (139, 445)        → smb_enum
  web (80, 443, 8080..) → web_enum
  ldap (389, 636)       → ad_enum
  kerberos (88)         → ad_enum
  rpc (135)             → smb_enum (Windows hint)
  ftp (21)              → ftp_enum  (TODO v4.1)
  ssh (22)              → ssh_enum  (TODO v4.1)
  rdp (3389)            → rdp_enum  (TODO v4.1)
  mssql (1433)          → db_enum   (TODO v4.1)
  mysql (3306)          → db_enum   (TODO v4.1)
  oracle (1521)         → db_enum   (TODO v4.1)
"""

from __future__ import annotations

import json
from pathlib import Path

# Mapeo: si algún port abierto está en este set → ese stack se activa
STACK_TRIGGERS: dict[str, set[int]] = {
    "smb":      {139, 445},
    "rpc":      {135},
    "web":      {80, 443, 8000, 8001, 8008, 8080, 8081, 8443, 8888, 5000, 5001, 9000, 9090},
    "ldap":     {389, 636},
    "kerberos": {88},
    "ftp":      {21},
    "ssh":      {22},
    "rdp":      {3389},
    "mssql":    {1433},
    "mysql":    {3306},
    "oracle":   {1521},
    "winrm":    {5985, 5986},
}

# Mapeo stack → módulo Python (None = TODO no implementado)
STACK_TO_MODULE: dict[str, str | None] = {
    "smb":      "phase2.modules.smb_enum",
    "rpc":      "phase2.modules.smb_enum",
    "web":      "phase2.modules.web_enum",
    "ldap":     "phase2.modules.ad_enum",
    "kerberos": "phase2.modules.ad_enum",
    "winrm":    "phase2.modules.smb_enum",  # WinRM enum vive en el mismo módulo
    "ftp":      None,
    "ssh":      None,
    "rdp":      None,
    "mssql":    None,
    "mysql":    None,
    "oracle":   None,
}


def detect_stacks(ports: list[dict]) -> list[str]:
    """Devuelve lista única de stacks detectados, en orden de prioridad."""
    open_ports = {int(p["port"]) for p in ports if str(p.get("state", "open")) == "open"}
    detected: list[str] = []
    # Orden de prioridad: AD primero (define el resto), luego servicios concretos.
    priority = ["kerberos", "ldap", "smb", "rpc", "winrm",
                "web", "mssql", "mysql", "oracle",
                "rdp", "ftp", "ssh"]
    for stack in priority:
        if open_ports & STACK_TRIGGERS[stack]:
            detected.append(stack)
    return detected


def plan_enumeration(ports: list[dict]) -> dict:
    """Devuelve {stacks_detected, modules_to_run, modules_pending}."""
    stacks = detect_stacks(ports)

    runnable: list[tuple[str, str]] = []   # (stack, module)
    seen_modules: set[str] = set()
    pending: list[str] = []

    for stack in stacks:
        mod = STACK_TO_MODULE.get(stack)
        if mod is None:
            pending.append(stack)
        elif mod not in seen_modules:
            runnable.append((stack, mod))
            seen_modules.add(mod)

    return {
        "stacks_detected":  stacks,
        "modules_to_run":   runnable,
        "modules_pending":  pending,  # stacks sin módulo todavía
    }


def main() -> int:
    """CLI: lee /tmp/clawsec_results.json y muestra el plan."""
    import argparse
    parser = argparse.ArgumentParser(description="ClawSec Phase 2 — enum dispatcher (plan only)")
    parser.add_argument("--input", default="/tmp/clawsec_results.json",
                        help="Phase 1 results JSON")
    args = parser.parse_args()

    fp = Path(args.input)
    if not fp.exists():
        print(f"❌ No encontrado: {fp}")
        return 1

    data = json.loads(fp.read_text())
    ports = data.get("nmap", {}).get("ports", [])
    target = data.get("meta", {}).get("target", "?")

    plan = plan_enumeration(ports)

    print(f"🦞 ClawSec Phase 2 — enumeration plan for {target}")
    print(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"Open ports: {len(ports)}")
    print(f"Stacks detected: {plan['stacks_detected'] or '(none)'}")
    print(f"Modules to run:")
    if not plan["modules_to_run"]:
        print("  (none — no enumeration modules apply)")
    for stack, mod in plan["modules_to_run"]:
        print(f"  • {stack:10s} → {mod}")
    if plan["modules_pending"]:
        print(f"Pending (no module yet): {plan['modules_pending']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
