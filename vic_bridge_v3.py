#!/usr/bin/env python3
"""
VIC Bridge v3.0 — ClawSec ↔ Vertex Intelligence Core
Vertex Coders LLC — 2026

Multi-backend insight engine:
  - xai     (Grok 4.1 Fast, OpenAI-compatible)  ← DEFAULT
  - groq    (free, fast, Llama 3.3 70B)
  - claude  (paid, premium quality fallback)
  - ollama  (local, offline last resort)
  - auto    (xai → groq → claude → ollama chain)

Endpoint FastAPI que recibe JSON de ClawSec y devuelve insight táctico.

Uso:
  VIC_BACKEND=groq    python3 vic_bridge_v3.py     # default
  VIC_BACKEND=claude  python3 vic_bridge_v3.py
  VIC_BACKEND=ollama  python3 vic_bridge_v3.py
  VIC_BACKEND=auto    python3 vic_bridge_v3.py
"""

import json
import os
import datetime
import urllib.request
import urllib.error
from pathlib import Path

# Cargar .env (busca en cwd y en /opt/vertex-intelligence-core)
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
    print("[-] pip install fastapi uvicorn")
    exit(1)

# ── Backends opcionales ────────────────────────────────────────────────────────
try:
    import anthropic
except ImportError:
    anthropic = None  # claude opcional

# Groq usa la SDK de OpenAI (compatibilidad)
try:
    from openai import OpenAI
except ImportError:
    OpenAI = None  # groq opcional

# ── Config ─────────────────────────────────────────────────────────────────────
BRIDGE_PORT       = int(os.getenv("VIC_BRIDGE_PORT", "5100"))
VIC_WRITEUPS_DIR  = Path("brain/datasets/raw_writeups")
VIC_DASHBOARD_URL = "http://localhost:5000"
BACKEND           = os.getenv("VIC_BACKEND", "xai").lower()  # default xai (Grok)
MAX_OUTPUT_TOKENS = int(os.getenv("VIC_MAX_TOKENS", "450"))

# Modelos por backend (actualizables sin tocar código)
XAI_MODEL     = os.getenv("VIC_XAI_MODEL",    "grok-4-1-fast-non-reasoning")
GROQ_MODEL    = os.getenv("VIC_GROQ_MODEL",   "llama-3.3-70b-versatile")
CLAUDE_MODEL  = os.getenv("VIC_CLAUDE_MODEL", "claude-haiku-4-5-20251001")
OLLAMA_MODEL  = os.getenv("VIC_OLLAMA_MODEL", "gemma3:1b")
OLLAMA_URL    = os.getenv("VIC_OLLAMA_URL",   "http://localhost:11434")

# Lazy clients
_xai_client       = None
_groq_client      = None
_anthropic_client = None


def _get_xai():
    global _xai_client
    if _xai_client is None:
        if not OpenAI:
            return None
        api_key = os.getenv("XAI_API_KEY")
        if not api_key:
            return None
        _xai_client = OpenAI(api_key=api_key, base_url="https://api.x.ai/v1")
    return _xai_client


def _get_groq():
    global _groq_client
    if _groq_client is None:
        if not OpenAI:
            return None
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            return None
        _groq_client = OpenAI(api_key=api_key, base_url="https://api.groq.com/openai/v1")
    return _groq_client


def _get_anthropic():
    global _anthropic_client
    if _anthropic_client is None:
        if not anthropic or not os.getenv("ANTHROPIC_API_KEY"):
            return None
        _anthropic_client = anthropic.Anthropic()
    return _anthropic_client


# ── System prompt (compartido entre backends) ──────────────────────────────────
SYSTEM_PROMPT = (
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


# ── Backend implementations ────────────────────────────────────────────────────

def query_xai(prompt: str) -> str | None:
    """Grok via xAI (paid). Returns None if unavailable."""
    client = _get_xai()
    if client is None:
        return None
    try:
        resp = client.chat.completions.create(
            model=XAI_MODEL,
            max_tokens=MAX_OUTPUT_TOKENS,
            temperature=0.3,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": prompt},
            ],
        )
        return resp.choices[0].message.content.strip()
    except Exception as e:
        print(f"[vic_bridge] xai error: {e}")
        return None


def query_groq(prompt: str) -> str | None:
    """Llama 3.3 70B via Groq (free tier). Returns None if unavailable."""
    client = _get_groq()
    if client is None:
        return None
    try:
        resp = client.chat.completions.create(
            model=GROQ_MODEL,
            max_tokens=MAX_OUTPUT_TOKENS,
            temperature=0.3,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": prompt},
            ],
        )
        return resp.choices[0].message.content.strip()
    except Exception as e:
        print(f"[vic_bridge] groq error: {e}")
        return None


def query_claude(prompt: str) -> str | None:
    """Claude Haiku/Sonnet via Anthropic. Returns None if unavailable."""
    client = _get_anthropic()
    if client is None:
        return None
    try:
        msg = client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=MAX_OUTPUT_TOKENS,
            temperature=0.3,
            system=[{"type": "text", "text": SYSTEM_PROMPT,
                     "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": prompt}],
        )
        return msg.content[0].text.strip()
    except Exception as e:
        print(f"[vic_bridge] claude error: {e}")
        return None


def query_ollama(prompt: str) -> str | None:
    """Modelo local via Ollama. Returns None if unavailable."""
    try:
        payload = json.dumps({
            "model":   OLLAMA_MODEL,
            "stream":  False,
            "system":  SYSTEM_PROMPT,
            "prompt":  prompt,
            "options": {"num_predict": MAX_OUTPUT_TOKENS, "temperature": 0.3},
        }).encode()
        req = urllib.request.Request(
            f"{OLLAMA_URL}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=180) as resp:
            data = json.loads(resp.read())
            return data.get("response", "").strip() or None
    except Exception as e:
        print(f"[vic_bridge] ollama error: {e}")
        return None


def query_insight(prompt: str) -> str:
    """Despacha al backend configurado, con fallback chain si BACKEND=auto."""

    if BACKEND == "xai":
        result = query_xai(prompt)
        return result or "⚠️ VIC offline — xAI unavailable. Set XAI_API_KEY in .env"

    if BACKEND == "groq":
        result = query_groq(prompt)
        return result or "⚠️ VIC offline — Groq unavailable. Set GROQ_API_KEY in .env"

    if BACKEND == "claude":
        result = query_claude(prompt)
        return result or "⚠️ VIC offline — Claude unavailable. Check ANTHROPIC_API_KEY."

    if BACKEND == "ollama":
        result = query_ollama(prompt)
        return result or f"⚠️ VIC offline — Ollama not responding at {OLLAMA_URL}"

    if BACKEND == "auto":
        # Cadena: xai → groq → claude → ollama
        for name, fn in [("xai", query_xai), ("groq", query_groq),
                         ("claude", query_claude), ("ollama", query_ollama)]:
            result = fn(prompt)
            if result:
                return f"[via {name}] {result}"
        return "⚠️ VIC offline — all backends failed."

    return f"⚠️ Unknown VIC_BACKEND={BACKEND!r}. Use: xai | groq | claude | ollama | auto"


# ── App ────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="VIC Bridge v3",
    description="ClawSec ↔ Vertex Intelligence Core (multi-backend) | Vertex Coders LLC",
    version="3.0.0"
)


def save_to_vic_dataset(clawsec_data: dict) -> Path:
    """JSON de ClawSec → writeup .md."""
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
        f"**Backend:** {BACKEND}",
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
        lines += ["", "## WHOIS", ""] + [f"- **{k}:** {v}" for k, v in whois.items()]
    if subs:
        lines += ["", "## Subdomains Found", ""] + [f"- {s.get('subdomain')} → {s.get('ip')}" for s in subs]

    md = "\n".join(lines)
    safe_target = target.replace(".", "_").replace("/", "_")
    ts_short    = timestamp[:19].replace(":", "-").replace("T", "_")
    fp = VIC_WRITEUPS_DIR / f"clawsec_{safe_target}_{ts_short}.md"
    fp.write_text(md, encoding="utf-8")
    return fp


def build_prompt(clawsec_data: dict) -> str:
    target = clawsec_data.get("meta", {}).get("target", "unknown")
    ports  = clawsec_data.get("nmap", {}).get("ports", [])

    critical = [p for p in ports if p.get("risk") == "Critical"]
    high     = [p for p in ports if p.get("risk") == "High"]

    findings = [
        f"Port {p.get('port')}: {p.get('product','')} {p.get('version','')} "
        f"[{p.get('risk')}] — {p.get('risk_reason','')}"
        for p in critical + high
    ]
    all_ports = [
        f"{p.get('port')}/{p.get('service','')} {p.get('product','')} {p.get('version','')}"
        for p in ports
    ]

    return f"""ClawSec just finished recon on: {target}

CRITICAL/HIGH FINDINGS:
{chr(10).join(findings) if findings else "None"}

ALL OPEN PORTS:
{chr(10).join(all_ports) if all_ports else "No open ports found"}

Based on your security knowledge (CVEs, HTB-style boxes, common misconfigs):
1. What is the most likely attack vector?
2. What exact command should the operator run next?"""


# ── Endpoints ──────────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    return {
        "service":    "VIC Bridge",
        "version":    "3.0.0",
        "company":    "Vertex Coders LLC",
        "backend":    BACKEND,
        "model": {
            "xai":    XAI_MODEL,
            "groq":   GROQ_MODEL,
            "claude": CLAUDE_MODEL,
            "ollama": OLLAMA_MODEL,
        },
        "endpoints": {
            "POST /vic/ingest": "Ingest ClawSec recon JSON, return insight",
            "GET  /vic/status": "Backend health checks",
        }
    }


@app.get("/vic/status")
async def status():
    """Health check para los 4 backends."""
    xai_ready     = bool(os.getenv("XAI_API_KEY") and OpenAI)
    groq_ready    = bool(os.getenv("GROQ_API_KEY") and OpenAI)
    claude_ready  = bool(os.getenv("ANTHROPIC_API_KEY") and anthropic)

    ollama_ready = False
    try:
        with urllib.request.urlopen(f"{OLLAMA_URL}/api/tags", timeout=2) as r:
            ollama_ready = bool(json.load(r).get("models"))
    except Exception:
        pass

    writeup_count = len(list(VIC_WRITEUPS_DIR.glob("*.md"))) if VIC_WRITEUPS_DIR.exists() else 0

    return {
        "vic_bridge":     "online",
        "active_backend": BACKEND,
        "backends": {
            "xai":    {"ready": xai_ready,    "model": XAI_MODEL},
            "groq":   {"ready": groq_ready,   "model": GROQ_MODEL},
            "claude": {"ready": claude_ready, "model": CLAUDE_MODEL},
            "ollama": {"ready": ollama_ready, "model": OLLAMA_MODEL},
        },
        "writeups_dir":   str(VIC_WRITEUPS_DIR),
        "writeup_count":  writeup_count,
        "timestamp":      datetime.datetime.utcnow().isoformat() + "Z",
    }


@app.post("/vic/ingest")
async def ingest(payload: dict):
    """Recibe ClawSec JSON → guarda writeup → consulta backend → devuelve insight."""
    try:
        target = payload.get("meta", {}).get("target", "unknown")
        print(f"[vic_bridge] Ingesting recon for: {target} (backend={BACKEND})")

        writeup_path = save_to_vic_dataset(payload)
        prompt       = build_prompt(payload)
        insight      = query_insight(prompt)

        ports    = payload.get("nmap", {}).get("ports", [])
        critical = sum(1 for p in ports if p.get("risk") == "Critical")
        high     = sum(1 for p in ports if p.get("risk") == "High")

        response = {
            "status":       "ingested",
            "target":       target,
            "backend":      BACKEND,
            "writeup_path": str(writeup_path),
            "stats": {
                "total_ports": len(ports),
                "critical":    critical,
                "high":        high,
            },
            "vic_insight":  insight,
            "timestamp":    datetime.datetime.utcnow().isoformat() + "Z",
        }

        print(f"[vic_bridge] ✅ Done — {critical} critical, {high} high | insight: {insight[:80]}...")
        return JSONResponse(content=response)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"VIC Bridge error: {e}")


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n🦞 VIC Bridge v3.0.0 | Vertex Coders LLC")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"Bridge port:       {BRIDGE_PORT}")
    print(f"Active backend:    {BACKEND}")
    print(f"  xai:    {XAI_MODEL:30s}  key={'set' if os.getenv('XAI_API_KEY') else 'NO'}")
    print(f"  groq:   {GROQ_MODEL:30s}  key={'set' if os.getenv('GROQ_API_KEY') else 'NO'}")
    print(f"  claude: {CLAUDE_MODEL:30s}  key={'set' if os.getenv('ANTHROPIC_API_KEY') else 'NO'}")
    print(f"  ollama: {OLLAMA_MODEL:30s}  url={OLLAMA_URL}")
    print(f"VIC writeups:      {VIC_WRITEUPS_DIR}")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("Waiting for ClawSec...\n")

    uvicorn.run(app, host="0.0.0.0", port=BRIDGE_PORT, log_level="info")
