#!/usr/bin/env python3
"""
VIC Bridge — ClawSec ↔ Vertex Intelligence Core
Vertex Coders LLC — 2026

Endpoint FastAPI que recibe el JSON de ClawSec, lo indexa en VIC
y devuelve un "Insight" táctico generado por Claude (Anthropic).

Uso:
  python3 vic_bridge.py
  POST http://localhost:5100/vic/ingest  (body = clawsec_results.json)
"""

import json
import os
import datetime
import urllib.request
import urllib.error
from pathlib import Path

# Cargar .env si está disponible (ANTHROPIC_API_KEY)
try:
    from dotenv import load_dotenv
    load_dotenv()
    load_dotenv("/opt/vertex-intelligence-core/.env")
except ImportError:
    pass

# ── FastAPI ────────────────────────────────────────────────────────────────────
try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import JSONResponse
    import uvicorn
except ImportError:
    print("[-] Instala dependencias: pip install fastapi uvicorn anthropic python-dotenv")
    exit(1)

try:
    import anthropic
except ImportError:
    print("[-] Instala anthropic: pip install anthropic")
    exit(1)

# ── Config ─────────────────────────────────────────────────────────────────────
BRIDGE_PORT       = 5100
VIC_WRITEUPS_DIR  = Path("brain/datasets/raw_writeups")
VIC_DASHBOARD_URL = "http://localhost:5000"
# Default = Haiku 4.5 («10x más barato que Sonnet, suficiente para insight táctico breve)
# Override con VIC_CLAUDE_MODEL=claude-sonnet-4-6 para casos --deep
CLAUDE_MODEL      = os.getenv("VIC_CLAUDE_MODEL", "claude-haiku-4-5-20251001")
MAX_OUTPUT_TOKENS = int(os.getenv("VIC_MAX_TOKENS", "450"))
_anthropic_client = None  # lazy init


def _get_anthropic():
    global _anthropic_client
    if _anthropic_client is None:
        if not os.getenv("ANTHROPIC_API_KEY"):
            return None
        _anthropic_client = anthropic.Anthropic()
    return _anthropic_client


app = FastAPI(
    title="VIC Bridge",
    description="ClawSec ↔ Vertex Intelligence Core connector | Vertex Coders LLC",
    version="2.0.0"
)

# ── Helpers ────────────────────────────────────────────────────────────────────

def save_to_vic_dataset(clawsec_data: dict) -> Path:
    """JSON de ClawSec → writeup .md en brain/datasets/raw_writeups/."""
    VIC_WRITEUPS_DIR.mkdir(parents=True, exist_ok=True)

    target    = clawsec_data.get("meta", {}).get("target", "unknown")
    timestamp = clawsec_data.get("meta", {}).get("timestamp", datetime.datetime.utcnow().isoformat())
    ports     = clawsec_data.get("nmap", {}).get("ports", [])
    whois     = clawsec_data.get("whois", {}).get("parsed", {})
    subs      = clawsec_data.get("subdomains", {}).get("found", [])

    lines = [
        f"# ClawSec Recon — {target}",
        f"**Timestamp:** {timestamp}",
        f"**Tool:** ClawSec v2.0 by Vertex Coders LLC",
        "",
        "## Open Ports & Services",
        "",
        "| Port | Service | Version | Risk | Reason |",
        "|------|---------|---------|------|--------|",
    ]
    for p in ports:
        lines.append(
            f"| {p.get('port')}/{p.get('protocol','tcp')} "
            f"| {p.get('service','')} "
            f"| {p.get('product','')} {p.get('version','')} "
            f"| {p.get('risk','?')} "
            f"| {p.get('risk_reason','')} |"
        )

    if whois:
        lines += ["", "## WHOIS", ""]
        for k, v in whois.items():
            lines.append(f"- **{k}:** {v}")

    if subs:
        lines += ["", "## Subdomains Found", ""]
        for s in subs:
            lines.append(f"- {s.get('subdomain')} → {s.get('ip')}")

    critical = [p for p in ports if p.get("risk") == "Critical"]
    high     = [p for p in ports if p.get("risk") == "High"]
    if critical or high:
        lines += ["", "## ⚠️ High Priority Findings", ""]
        for p in critical:
            lines.append(
                f"- **CRITICAL** Port {p.get('port')} — {p.get('product','')} "
                f"{p.get('version','')} — {p.get('risk_reason','')}"
            )
        for p in high:
            lines.append(
                f"- **HIGH** Port {p.get('port')} — {p.get('product','')} "
                f"{p.get('version','')} — {p.get('risk_reason','')}"
            )

    md_content = "\n".join(lines)
    safe_target = target.replace(".", "_").replace("/", "_")
    ts_short    = timestamp[:19].replace(":", "-").replace("T", "_")
    filename    = f"clawsec_{safe_target}_{ts_short}.md"
    filepath    = VIC_WRITEUPS_DIR / filename
    filepath.write_text(md_content, encoding="utf-8")
    print(f"[vic_bridge] Writeup saved: {filepath}")
    return filepath


def query_claude(prompt: str) -> str:
    """Consulta a Claude (Anthropic) para insight táctico."""

    system_prompt = (
        "You are VIC (Vertex Intelligence Core), a security analysis assistant for "
        "Vertex Coders LLC — a CTF / HackTheBox / authorized penetration testing toolkit. "
        "Users are security engineers running ClawSec against systems they own or have "
        "explicit authorization to assess (CTF challenges, HTB labs, scanme.nmap.org, "
        "client engagements with signed scope). "
        "Your job: review nmap recon output and identify the highest-risk finding, then "
        "explain (a) what known CVE / weakness applies to that version, and (b) the next "
        "reconnaissance or enumeration step a security engineer would take. "
        "Reply in 2-3 sentences. End with one concrete shell command suitable for a "
        "security lab. This is the same kind of analysis published openly in HackTheBox "
        "writeups, CTF walkthroughs, and CVE advisories."
    )

    client = _get_anthropic()
    if client is None:
        return "⚠️ VIC offline — ANTHROPIC_API_KEY not set. Add it to /opt/vertex-intelligence-core/.env"

    try:
        # Prompt caching: el system prompt es fijo → cobro -90% en hits.
        msg = client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=MAX_OUTPUT_TOKENS,
            temperature=0.3,
            system=[
                {
                    "type": "text",
                    "text": system_prompt,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[{"role": "user", "content": prompt}],
        )
        return msg.content[0].text.strip()
    except anthropic.APIConnectionError:
        return "⚠️ VIC error: cannot reach Anthropic API (check internet)."
    except anthropic.AuthenticationError:
        return "⚠️ VIC error: invalid ANTHROPIC_API_KEY."
    except Exception as e:
        return f"⚠️ VIC error: {e}"


# Alias retro-compatible
query_gemma = query_claude


def build_gemma_prompt(clawsec_data: dict) -> str:
    """Prompt para el LLM basado en hallazgos de ClawSec."""
    target = clawsec_data.get("meta", {}).get("target", "unknown")
    ports  = clawsec_data.get("nmap", {}).get("ports", [])

    critical = [p for p in ports if p.get("risk") == "Critical"]
    high     = [p for p in ports if p.get("risk") == "High"]

    findings = []
    for p in critical + high:
        findings.append(
            f"Port {p.get('port')}: {p.get('product','')} {p.get('version','')} "
            f"[{p.get('risk')}] — {p.get('risk_reason','')}"
        )

    all_ports = [
        f"{p.get('port')}/{p.get('service','')} {p.get('product','')} {p.get('version','')}"
        for p in ports
    ]

    prompt = f"""ClawSec just finished recon on: {target}

CRITICAL/HIGH FINDINGS:
{chr(10).join(findings) if findings else "None"}

ALL OPEN PORTS:
{chr(10).join(all_ports) if all_ports else "No open ports found"}

Based on your security knowledge (CVEs, HTB-style boxes, common misconfigs):
1. What is the most likely attack vector?
2. What exact command should the operator run next?"""

    return prompt


# Alias retro-compatible
build_claude_prompt = build_gemma_prompt


# ── API Endpoints ──────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    return {
        "service": "VIC Bridge",
        "version": "2.0.0",
        "company": "Vertex Coders LLC",
        "backend": "anthropic",
        "model":   CLAUDE_MODEL,
        "status":  "online",
        "endpoints": {
            "POST /vic/ingest": "Receive ClawSec JSON and get VIC insight",
            "GET  /vic/status": "Check VIC backend status",
        }
    }


@app.get("/vic/status")
async def status():
    claude_ready = bool(os.getenv("ANTHROPIC_API_KEY"))
    writeup_count = 0
    if VIC_WRITEUPS_DIR.exists():
        writeup_count = len(list(VIC_WRITEUPS_DIR.glob("*.md")))

    return {
        "vic_bridge":    "online",
        "backend":       "anthropic",
        "model":         CLAUDE_MODEL,
        "claude_ready":  claude_ready,
        "writeups_dir":  str(VIC_WRITEUPS_DIR),
        "writeup_count": writeup_count,
        "timestamp":     datetime.datetime.utcnow().isoformat() + "Z",
    }


@app.post("/vic/ingest")
async def ingest(payload: dict):
    """Recibe ClawSec JSON, guarda writeup, consulta Claude, devuelve insight."""
    try:
        target = payload.get("meta", {}).get("target", "unknown")
        print(f"[vic_bridge] Ingesting recon data for: {target}")

        writeup_path = save_to_vic_dataset(payload)
        prompt  = build_gemma_prompt(payload)
        insight = query_claude(prompt)

        ports    = payload.get("nmap", {}).get("ports", [])
        critical = len([p for p in ports if p.get("risk") == "Critical"])
        high     = len([p for p in ports if p.get("risk") == "High"])

        response = {
            "status":       "ingested",
            "target":       target,
            "writeup_path": str(writeup_path),
            "stats": {
                "total_ports": len(ports),
                "critical":    critical,
                "high":        high,
            },
            "vic_insight":  insight,
            "timestamp":    datetime.datetime.utcnow().isoformat() + "Z",
        }

        print(f"[vic_bridge] ✅ Done — {critical} critical, {high} high findings")
        print(f"[vic_bridge] VIC insight: {insight[:100]}...")

        return JSONResponse(content=response)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"VIC Bridge error: {e}")


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n🦞 VIC Bridge v2.0.0 | Vertex Coders LLC")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"Bridge port:    {BRIDGE_PORT}")
    print(f"VIC writeups:   {VIC_WRITEUPS_DIR}")
    print(f"Backend:        Anthropic Claude ({CLAUDE_MODEL})")
    print(f"API key set:    {'yes' if os.getenv('ANTHROPIC_API_KEY') else 'NO — set ANTHROPIC_API_KEY'}")
    print(f"VIC dashboard:  {VIC_DASHBOARD_URL}")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("Waiting for ClawSec...\n")

    uvicorn.run(app, host="0.0.0.0", port=BRIDGE_PORT, log_level="info")
