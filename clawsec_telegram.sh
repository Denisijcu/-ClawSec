#!/bin/bash
# =============================================================================
# clawsec_telegram.sh — Standalone /clawsec runner
# Vertex Coders LLC
#
# Hace todo el flow sin gateway/agente:
#   1. scope_guard
#   2. recon.py (que internamente llama a vic_bridge → Claude)
#   3. Formatea reporte y lo envía al Telegram bot
#
# Uso:
#   ./clawsec_telegram.sh <target> [scan_type] [--htb]
#
# Ejemplos:
#   ./clawsec_telegram.sh scanme.nmap.org
#   ./clawsec_telegram.sh scanme.nmap.org full
#   ./clawsec_telegram.sh 10.10.11.42 quick --htb
# =============================================================================

set -e

# ── Config ──────────────────────────────────────────────────────────────────
CLAWSEC_DIR="/opt/clawsec"
RESULTS_FILE="/tmp/clawsec_results.json"
BOT_TOKEN="8731904250:AAFx1lYUXKwRRsti4rqVv8YG4ePNqeLR6pk"
CHAT_ID="${CLAWSEC_CHAT_ID:-8732455857}"  # override con env var si quieres

# ── Args ────────────────────────────────────────────────────────────────────
TARGET="${1:-}"
SCAN_TYPE="${2:-quick}"
HTB_FLAG=""

if [ -z "$TARGET" ]; then
    echo "Uso: $0 <target> [quick|full|stealth] [--htb]"
    exit 1
fi

# Detectar --htb en cualquier posición
for arg in "$@"; do
    if [ "$arg" = "--htb" ]; then
        HTB_FLAG="--allow-lab"
    fi
done

cd "$CLAWSEC_DIR"

echo "🦞 ClawSec runner | target=$TARGET scan=$SCAN_TYPE htb=${HTB_FLAG:-no}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── Step 1: Scope guard ─────────────────────────────────────────────────────
echo "[1/3] Scope guard..."
if ! python3 scope_guard.py $HTB_FLAG "$TARGET" > /tmp/scope_result.txt 2>&1; then
    REASON=$(cat /tmp/scope_result.txt)
    echo "❌ BLOCKED: $REASON"
    # Notificar el bloqueo a Telegram
    curl -s -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
        --data-urlencode "chat_id=${CHAT_ID}" \
        --data-urlencode "text=🦞 ClawSec — Target bloqueado por scope_guard
Target: ${TARGET}
Razón: ${REASON}

⚠️ Usa --htb para HTB/lab ranges, o añade el target a ~/.clawsec/allowlist.txt" > /dev/null
    exit 1
fi
echo "✅ ALLOWED"

# ── Step 2: Recon (incluye llamada a vic_bridge → Claude) ───────────────────
echo "[2/3] Recon (nmap + whois + VIC bridge)..."
python3 recon.py --target "$TARGET" --scan "$SCAN_TYPE" --modules ports,whois || {
    echo "❌ recon.py falló"
    exit 1
}

if [ ! -f "$RESULTS_FILE" ]; then
    echo "❌ no se generó $RESULTS_FILE"
    exit 1
fi

# ── Step 3: Format report and send to Telegram ──────────────────────────────
echo "[3/3] Enviando reporte a Telegram..."
python3 <<PYEOF
import json, urllib.request, urllib.parse, sys

BOT_TOKEN = "${BOT_TOKEN}"
CHAT_ID   = "${CHAT_ID}"

with open("${RESULTS_FILE}") as f:
    data = json.load(f)

target  = data.get("meta", {}).get("target", "?")
scan    = data.get("meta", {}).get("scan_type", "?")
ports   = data.get("nmap", {}).get("ports", [])
insight = data.get("vic_insight", "(VIC bridge no respondió — ¿está corriendo en :5100?)")

# Tabla compacta de puertos (Telegram-friendly, sin Markdown table)
port_lines = []
for p in sorted(ports, key=lambda x: {"Critical":0,"High":1,"Medium":2,"Low":3,"Info":4}.get(x.get("risk","Info"), 9)):
    port_lines.append(
        f"• {p.get('port')}/{p.get('protocol','tcp')} {p.get('service','?')} - "
        f"{p.get('product','')} {p.get('version','')} [{p.get('risk','?')}]"
    )

critical = sum(1 for p in ports if p.get("risk") == "Critical")
high     = sum(1 for p in ports if p.get("risk") == "High")

msg = f"""🦞 ClawSec Report | Vertex Coders LLC
━━━━━━━━━━━━━━━━━━━━━━━━
Target: {target}
Scan: {scan} | Ports: {len(ports)} | Critical: {critical} | High: {high}

📋 Open Ports:
{chr(10).join(port_lines) if port_lines else "(no open ports detected)"}

🎯 Vertex Intelligence (Claude Haiku 4.5):
{insight}

━━━━━━━━━━━━━━━━━━━━━━━━
⚠️ Authorized use only | github.com/Denisijcu/clawsec"""

# Telegram límite 4096 chars
if len(msg) > 4000:
    msg = msg[:3950] + "\n\n... (truncated)"

url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
payload = urllib.parse.urlencode({"chat_id": CHAT_ID, "text": msg}).encode()

try:
    with urllib.request.urlopen(url, data=payload, timeout=15) as resp:
        result = json.load(resp)
        if result.get("ok"):
            print(f"✅ Telegram message_id={result['result']['message_id']}")
        else:
            print(f"❌ Telegram dijo: {result}")
            sys.exit(1)
except urllib.error.HTTPError as e:
    print(f"❌ HTTP {e.code}: {e.read().decode()}")
    sys.exit(1)
except Exception as e:
    print(f"❌ {type(e).__name__}: {e}")
    sys.exit(1)
PYEOF

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🦞 ClawSec done."
