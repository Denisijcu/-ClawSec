
#!/usr/bin/env python3
"""
VIC Bridge — ClawSec ↔ Vertex Intelligence Core
Vertex Coders LLC — 2026

Endpoint FastAPI que recibe el JSON de ClawSec,
lo indexa en VIC y devuelve un "Insight" de Gemma.

Uso:
  # Levantar el bridge (en el HP Omen donde corre VIC)
  python3 vic_bridge.py

  # ClawSec lo llama automáticamente al terminar recon
  POST http://localhost:5100/vic/ingest
  Body: clawsec_results.json
"""

import json
import os
import datetime
import urllib.request
import urllib.error
from pathlib import Path

# ── FastAPI ────────────────────────────────────────────────────────────────────
try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import JSONResponse
    import uvicorn
except ImportError:
    print("[-] Instala dependencias: pip install fastapi uvicorn")
    exit(1)

# ── Config ─────────────────────────────────────────────────────────────────────
BRIDGE_PORT        = 5100                          # Puerto del bridge (distinto al VIC dashboard 5000)
VIC_WRITEUPS_DIR   = Path("brain/datasets/raw_writeups")  # Carpeta de VIC
VIC_DASHBOARD_URL  = "http://localhost:5000"       # Dashboard de VIC
GEMMA_URL          = "http://localhost:1234/v1/chat/completions"  # LM Studio
GEMMA_MODEL        = "gemma-3-4b-it"

app = FastAPI(
    title="VIC Bridge",
    description="ClawSec ↔ Vertex Intelligence Core connector | Vertex Coders LLC",
    version="1.0.0"
)

# ── Helpers ────────────────────────────────────────────────────────────────────

def save_to_vic_dataset(clawsec_data: dict) -> Path:
    """
    Convierte el JSON de ClawSec a un writeup .md
    y lo guarda en brain/datasets/raw_writeups/ de VIC.
    """
    VIC_WRITEUPS_DIR.mkdir(parents=True, exist_ok=True)

    target    = clawsec_data.get("meta", {}).get("target", "unknown")
    timestamp = clawsec_data.get("meta", {}).get("timestamp", datetime.datetime.utcnow().isoformat())
    ports     = clawsec_data.get("nmap", {}).get("ports", [])
    whois     = clawsec_data.get("whois", {}).get("parsed", {})
    subs      = clawsec_data.get("subdomains", {}).get("found", [])

    # Construir el writeup en markdown
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

    # Critical findings summary
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

    # Guardar con timestamp para no sobrescribir
    safe_target = target.replace(".", "_").replace("/", "_")
    ts_short    = timestamp[:19].replace(":", "-").replace("T", "_")
    filename    = f"clawsec_{safe_target}_{ts_short}.md"
    filepath    = VIC_WRITEUPS_DIR / filename

    filepath.write_text(md_content, encoding="utf-8")
    print(f"[vic_bridge] Writeup saved: {filepath}")
    return filepath


def query_gemma(prompt: str) -> str:
    """Consulta a Gemma 3-4B via LM Studio para obtener el insight."""

    system_prompt = """You are VIC (Vertex Intelligence Core), the RAG-powered security brain of Vertex Coders LLC.
You receive recon data from ClawSec and provide tactical attack insights based on your knowledge base.
Be concise, technical, and actionable. Focus on the most exploitable finding.
Format: 2-3 sentences max. Always end with the exact next command to run."""

    payload = json.dumps({
        "model":    GEMMA_MODEL,
        "messages": [
            {"role": "system",  "content": system_prompt},
            {"role": "user",    "content": prompt},
        ],
        "max_tokens":  300,
        "temperature": 0.3,
    }).encode()

    req = urllib.request.Request(
        GEMMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            data = json.loads(resp.read())
            return data["choices"][0]["message"]["content"].strip()
    except urllib.error.URLError:
        return "⚠️ VIC offline — LM Studio not running on port 1234. Start LM Studio and load Gemma 3-4B."
    except Exception as e:
        return f"⚠️ VIC error: {e}"


def build_gemma_prompt(clawsec_data: dict) -> str:
    """Construye el prompt para Gemma basado en los hallazgos de ClawSec."""

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

Based on your knowledge base of HTB writeups and CVE database:
1. What is the most likely attack vector?
2. What exact command should the operator run next?"""

    return prompt


# ── API Endpoints ──────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    return {
        "service": "VIC Bridge",
        "version": "1.0.0",
        "company": "Vertex Coders LLC",
        "status":  "online",
        "endpoints": {
            "POST /vic/ingest": "Receive ClawSec JSON and get VIC insight",
            "GET  /vic/status": "Check VIC and Gemma status",
        }
    }


@app.get("/vic/status")
async def status():
    """Check if VIC components are running."""

    # Check Gemma/LM Studio
    gemma_online = False
    try:
        req = urllib.request.Request(
            "http://localhost:1234/v1/models",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5):
            gemma_online = True
    except Exception:
        pass

    # Check writeups dir
    writeup_count = 0
    if VIC_WRITEUPS_DIR.exists():
        writeup_count = len(list(VIC_WRITEUPS_DIR.glob("*.md")))

    return {
        "vic_bridge":    "online",
        "gemma_lm":      "online" if gemma_online else "offline — start LM Studio",
        "writeups_dir":  str(VIC_WRITEUPS_DIR),
        "writeup_count": writeup_count,
        "timestamp":     datetime.datetime.utcnow().isoformat() + "Z",
    }


@app.post("/vic/ingest")
async def ingest(payload: dict):
    """
    Main endpoint — receives ClawSec JSON, saves writeup, queries Gemma.

    Expected body: contents of /tmp/clawsec_results.json
    Returns: VIC insight + writeup path
    """
    try:
        target = payload.get("meta", {}).get("target", "unknown")
        print(f"[vic_bridge] Ingesting recon data for: {target}")

        # 1. Save to VIC dataset
        writeup_path = save_to_vic_dataset(payload)

        # 2. Build prompt and query Gemma
        prompt  = build_gemma_prompt(payload)
        insight = query_gemma(prompt)

        # 3. Summary stats
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
    print("\n🦞 VIC Bridge v1.0.0 | Vertex Coders LLC")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"Bridge port:    {BRIDGE_PORT}")
    print(f"VIC writeups:   {VIC_WRITEUPS_DIR}")
    print(f"Gemma endpoint: {GEMMA_URL}")
    print(f"VIC dashboard:  {VIC_DASHBOARD_URL}")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("Waiting for ClawSec...\n")

    uvicorn.run(app, host="0.0.0.0", port=BRIDGE_PORT, log_level="info")
