
#!/usr/bin/env python3
"""
VIC Hook — Agregar al final de recon.py
Vertex Coders LLC — 2026

Este código va AL FINAL de la función main() en recon.py,
justo antes del print("DONE | ..."):

Reemplaza estas líneas en recon.py:

    # Print summary to stdout for OpenClaw to read
    port_count = results["nmap"].get("port_count", 0)
    sub_count = results["subdomains"].get("count", 0)
    print(f"DONE | ports={port_count} | subdomains={sub_count} | output={OUTPUT_FILE}")

Por estas:

    # ── VIC Bridge hook ───────────────────────────────────────────────────────
    port_count = results["nmap"].get("port_count", 0)
    sub_count  = results["subdomains"].get("count", 0)
    
    vic_insight = send_to_vic_bridge(results)
    if vic_insight:
        results["vic_insight"] = vic_insight
        OUTPUT_FILE.write_text(json.dumps(results, indent=2))  # update with insight
    
    print(f"DONE | ports={port_count} | subdomains={sub_count} | output={OUTPUT_FILE}")
    if vic_insight:
        print(f"VIC_INSIGHT | {vic_insight[:120]}...")
"""

# ── Pegar esta función en recon.py (antes de main()) ──────────────────────────

VIC_BRIDGE_URL = "http://localhost:5100/vic/ingest"
VIC_BRIDGE_TIMEOUT = 10  # segundos — no bloqueamos el recon si VIC está offline

def send_to_vic_bridge(results: dict) -> str:
    """
    Envía los resultados de ClawSec al VIC Bridge.
    Retorna el insight de Gemma o None si VIC está offline.
    Es non-blocking — si VIC no responde en 10s, seguimos.
    """
    import urllib.request
    import urllib.error

    try:
        payload = json.dumps(results).encode()
        req = urllib.request.Request(
            VIC_BRIDGE_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=VIC_BRIDGE_TIMEOUT) as resp:
            data = json.loads(resp.read())
            insight = data.get("vic_insight", "")
            print(f"[recon] ✅ VIC Bridge received data for {data.get('target')}", file=sys.stderr)
            return insight
    except urllib.error.URLError:
        print(f"[recon] ⚠️ VIC Bridge offline (localhost:5100) — skipping", file=sys.stderr)
        return None
    except Exception as e:
        print(f"[recon] ⚠️ VIC Bridge error: {e}", file=sys.stderr)
        return None
