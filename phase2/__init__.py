"""
ClawSec Phase 2 — Enumeration & Exploitation Guidance
Vertex Coders LLC | 2026

Phase 1 (recon.py) does port scanning and risk scoring.
Phase 2 takes those results and:
  1. Dispatches deeper enumeration based on detected stack.
  2. Asks VIC (LLM) what the highest-value path is.
  3. Suggests exploit chain with copy-paste commands.
  4. Tracks session state per target so context persists across runs.

Modes:
  - guided  (default): clawSec runs passive enum, asks before active probes.
  - assisted: clawSec only suggests, user runs everything manually.
  - auto: dangerous, only with --i-know-what-im-doing flag.
"""

__version__ = "0.1.0-alpha"
