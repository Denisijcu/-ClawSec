#!/usr/bin/env python3
"""
ClawSec Phase 2 — Main runner / orchestrator
Vertex Coders LLC

Usage:
  # Read phase 1 results, run all applicable enum modules, then ask advisor
  python3 phase2_runner.py <target>

  # Only run dispatcher (show plan, no execution)
  python3 phase2_runner.py <target> --plan-only

  # Run specific module(s) by name
  python3 phase2_runner.py <target> --only smb_enum,web_enum

  # Skip the LLM advisor (just run enumerations)
  python3 phase2_runner.py <target> --no-advisor

  # Show current session state
  python3 phase2_runner.py <target> --show-session
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from phase2 import session as sess
from phase2 import enum_dispatcher
from phase2 import exploit_advisor


def ingest_phase1(target: str, results_path: str = "/tmp/clawsec_results.json") -> dict:
    """Carga el JSON de phase 1 y lo mete en la session."""
    fp = Path(results_path)
    if not fp.exists():
        return {"status": "no_phase1", "msg": f"{results_path} not found"}

    data = json.loads(fp.read_text())
    s = sess.load(target)

    s["phase1"]["ports"]    = data.get("nmap", {}).get("ports", [])
    s["phase1"]["raw_nmap"] = data.get("nmap", {}).get("xml", "")
    plan = enum_dispatcher.plan_enumeration(s["phase1"]["ports"])
    s["phase1"]["stacks"]   = plan["stacks_detected"]

    sess.save(target, s)
    return {"status": "ok", "ports": len(s["phase1"]["ports"]),
            "stacks": s["phase1"]["stacks"]}


def run_module(module_name: str, target: str, ports: list[dict]) -> dict:
    """Importa dinámicamente el módulo y ejecuta su run()."""
    try:
        mod = importlib.import_module(module_name)
    except Exception as e:
        return {"status": "error", "msg": f"failed to import {module_name}: {e}"}

    try:
        return mod.run(target, ports)
    except Exception as e:
        return {"status": "error", "msg": f"{module_name}.run() failed: {e}"}


def main() -> int:
    ap = argparse.ArgumentParser(description="ClawSec Phase 2 runner")
    ap.add_argument("target", help="Target IP or hostname")
    ap.add_argument("--input", default="/tmp/clawsec_results.json",
                    help="Phase 1 JSON results")
    ap.add_argument("--plan-only", action="store_true",
                    help="Show enumeration plan, don't execute")
    ap.add_argument("--only", default=None,
                    help="Comma-separated module names to run (e.g. smb_enum,web_enum)")
    ap.add_argument("--no-advisor", action="store_true",
                    help="Skip LLM advisor at the end")
    ap.add_argument("--show-session", action="store_true",
                    help="Print current session state and exit")
    args = ap.parse_args()

    if args.show_session:
        s = sess.load(args.target)
        print(json.dumps(s, indent=2))
        return 0

    print(f"🦞 ClawSec Phase 2 | target={args.target}")
    print("━" * 60)

    # 1. Ingest phase 1
    print("[1/4] Ingesting phase 1 recon results...")
    ing = ingest_phase1(args.target, args.input)
    if ing["status"] != "ok":
        print(f"❌ {ing.get('msg')}")
        print("    Run phase 1 first:")
        print(f"    python3 /opt/clawsec/recon.py --target {args.target} --scan quick")
        return 1
    print(f"    ✅ {ing['ports']} ports, stacks: {ing['stacks']}")

    # 2. Plan
    s = sess.load(args.target)
    plan = enum_dispatcher.plan_enumeration(s["phase1"]["ports"])
    print(f"\n[2/4] Enumeration plan:")
    if not plan["modules_to_run"]:
        print("    (no applicable modules — phase 1 didn't detect SMB/Web/AD/etc.)")
        if args.no_advisor:
            return 0
    for stack, mod in plan["modules_to_run"]:
        print(f"    • {stack:10s} → {mod}")
    if plan["modules_pending"]:
        print(f"    Pending (not yet implemented): {plan['modules_pending']}")

    if args.plan_only:
        print("\n[plan-only] Stopping here.")
        return 0

    # 3. Execute modules
    print(f"\n[3/4] Running enumeration modules...")
    only = set(args.only.split(",")) if args.only else None
    enum_results = {}
    for stack, mod_name in plan["modules_to_run"]:
        short_name = mod_name.rsplit(".", 1)[-1]
        if only and short_name not in only:
            print(f"    ⏭️  skip {short_name} (not in --only)")
            continue
        print(f"\n    ▶ {short_name}")
        res = run_module(mod_name, args.target, s["phase1"]["ports"])
        enum_results[short_name] = res
        if res.get("status") == "error":
            print(f"    ❌ {res.get('msg')}")

    # 4. Advisor
    if not args.no_advisor:
        print(f"\n[4/4] Asking VIC advisor for next steps...")
        adv = exploit_advisor.get_advice(args.target)
        if adv["status"] != "ok":
            print(f"    ❌ Advisor unavailable: {adv.get('msg')}")
        else:
            advice = adv["advice"]
            print()
            print("━" * 60)
            print("🎯 VIC ADVISOR — NEXT STEPS")
            print("━" * 60)
            if "raw_response" in advice:
                print(advice["raw_response"])
            else:
                print(f"\n🥇 TOP PRIORITY: {advice.get('top_priority','?')}")
                print(f"\n💡 WHY: {advice.get('why','?')}")
                print(f"\n💻 NEXT COMMAND:")
                print(f"   $ {advice.get('next_command','?')}")
                print(f"\n✅ EXPECTED: {advice.get('expected_outcome','?')}")
                print(f"\n🔁 IF BLOCKED: {advice.get('if_blocked','?')}")
                print(f"\n🥈 PRIORITY 2: {advice.get('priority_2','?')}")
            print("━" * 60)

    print(f"\n🦞 Phase 2 done. Session: ~/.clawsec/sessions/{args.target}.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
