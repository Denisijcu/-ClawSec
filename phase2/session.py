#!/usr/bin/env python3
"""
ClawSec Phase 2 — Session State Manager
Vertex Coders LLC

Persists context per target across multiple clawSec runs.
This is what makes clawSec smart: it remembers what worked, what failed,
what credentials were found, what paths are dead ends.

Storage: ~/.clawsec/sessions/<target_safe>.json
"""

from __future__ import annotations

import json
import os
import datetime
from pathlib import Path
from typing import Any

SESSION_DIR = Path(os.path.expanduser("~/.clawsec/sessions"))


def _safe_name(target: str) -> str:
    """Convert target into safe filename."""
    return target.replace("/", "_").replace(":", "_").replace(" ", "_")


def session_path(target: str) -> Path:
    SESSION_DIR.mkdir(parents=True, exist_ok=True)
    return SESSION_DIR / f"{_safe_name(target)}.json"


def load(target: str) -> dict[str, Any]:
    """Load session for target. Returns empty dict if first time."""
    fp = session_path(target)
    if not fp.exists():
        return _new_session(target)
    try:
        return json.loads(fp.read_text())
    except (json.JSONDecodeError, OSError):
        # Corrupt session, start fresh but keep backup
        fp.rename(fp.with_suffix(".json.corrupt"))
        return _new_session(target)


def save(target: str, session: dict[str, Any]) -> None:
    fp = session_path(target)
    session["updated_at"] = datetime.datetime.utcnow().isoformat() + "Z"
    fp.write_text(json.dumps(session, indent=2, default=str))


def _new_session(target: str) -> dict[str, Any]:
    return {
        "target":        target,
        "created_at":    datetime.datetime.utcnow().isoformat() + "Z",
        "updated_at":    datetime.datetime.utcnow().isoformat() + "Z",
        "phase1": {                    # filled by recon.py output ingest
            "ports":    [],
            "stacks":   [],            # ["smb", "web", "ad", ...]
            "raw_nmap": "",
        },
        "phase2": {
            "enum_runs":    [],        # list of {module, started_at, status, output_path}
            "credentials":  [],        # list of {user, hash_or_pass, source}
            "shares":       [],        # SMB shares discovered
            "subdomains":   [],
            "endpoints":    [],        # web paths, APIs
            "users":        [],        # enumerated user accounts
            "groups":       [],
            "kerberos":     {"asrep_hashes": [], "tgs_hashes": []},
        },
        "shells": [],                  # active shells obtained
        "exploits_tried": [],          # what we've attempted
        "dead_ends": [],               # paths confirmed not working
        "vic_history": [],             # LLM conversation about this target
        "notes": "",                   # user can append observations
    }


def add_enum_run(target: str, module: str, status: str, output: dict | None = None) -> None:
    s = load(target)
    s["phase2"]["enum_runs"].append({
        "module":     module,
        "started_at": datetime.datetime.utcnow().isoformat() + "Z",
        "status":     status,
        "output":     output or {},
    })
    save(target, s)


def add_credential(target: str, user: str, secret: str, source: str, kind: str = "password") -> None:
    s = load(target)
    cred = {
        "user":       user,
        "secret":     secret,
        "kind":       kind,             # password | nthash | kerberos | ssh-key
        "source":     source,           # module that found it
        "found_at":   datetime.datetime.utcnow().isoformat() + "Z",
    }
    if cred not in s["phase2"]["credentials"]:
        s["phase2"]["credentials"].append(cred)
        save(target, s)


def add_share(target: str, share: str, access: str = "unknown") -> None:
    s = load(target)
    entry = {"share": share, "access": access}
    if entry not in s["phase2"]["shares"]:
        s["phase2"]["shares"].append(entry)
        save(target, s)


def add_users(target: str, users: list[str]) -> None:
    s = load(target)
    existing = set(s["phase2"]["users"])
    new = [u for u in users if u not in existing]
    if new:
        s["phase2"]["users"].extend(new)
        save(target, s)


def add_dead_end(target: str, description: str) -> None:
    s = load(target)
    if description not in s["dead_ends"]:
        s["dead_ends"].append(description)
        save(target, s)


def list_sessions() -> list[str]:
    if not SESSION_DIR.exists():
        return []
    return sorted([p.stem for p in SESSION_DIR.glob("*.json")])


if __name__ == "__main__":
    # Self-test
    test_target = "test.local"
    s = load(test_target)
    print(f"Loaded session: {s['target']} (created {s['created_at']})")
    add_credential(test_target, "alice", "Password123!", "smb_enum", "password")
    add_share(test_target, "IPC$", "READ")
    add_users(test_target, ["alice", "bob", "administrator"])
    s = load(test_target)
    print(json.dumps(s, indent=2)[:500] + "...")
    print(f"\n✅ Session saved at: {session_path(test_target)}")
