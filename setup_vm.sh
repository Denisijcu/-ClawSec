#!/usr/bin/env bash
# ============================================================
# ClawSec VM Setup Script
# Vertex Coders LLC — 2026
# Ubuntu 24.04 LTS
# Run as: bash setup_vm.sh
# ============================================================

set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }

echo ""
echo "  🦞 ClawSec Setup — Vertex Coders LLC"
echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── 1. System deps ─────────────────────────────────────────
log "Updating system packages..."
sudo apt update -qq && sudo apt upgrade -y -qq

log "Installing dependencies..."
sudo apt install -y -qq \
    nmap \
    whois \
    python3 \
    python3-pip \
    curl \
    git \
    build-essential

# ── 2. Node.js 20 (required by OpenClaw) ──────────────────
if ! command -v node &>/dev/null; then
    log "Installing Node.js 20..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - -q
    sudo apt install -y -qq nodejs
else
    NODE_VER=$(node --version)
    log "Node.js already installed: $NODE_VER"
fi

# ── 3. pnpm (OpenClaw prefers pnpm) ───────────────────────
if ! command -v pnpm &>/dev/null; then
    log "Installing pnpm..."
    npm install -g pnpm --silent
else
    log "pnpm already installed: $(pnpm --version)"
fi

# ── 4. OpenClaw ────────────────────────────────────────────
if [ ! -f "$HOME/.openclaw/config.json" ]; then
    log "Installing OpenClaw..."
    curl -fsSL https://openclaw.ai/install.sh | bash
    warn "OpenClaw installed. Run 'openclaw onboard' manually to configure your API key and Telegram channel."
else
    log "OpenClaw already configured at ~/.openclaw"
fi

# ── 5. ClawSec skill ───────────────────────────────────────
SKILL_DIR="$HOME/.openclaw/skills/clawsec"
log "Installing ClawSec skill..."
mkdir -p "$SKILL_DIR"

# Copy skill files (assumes you cloned the repo next to this script)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "$SCRIPT_DIR/SKILL.md" ]; then
    cp "$SCRIPT_DIR/SKILL.md"      "$SKILL_DIR/SKILL.md"
    cp "$SCRIPT_DIR/recon.py"      "$SKILL_DIR/recon.py"
    cp "$SCRIPT_DIR/scope_guard.py" "$SKILL_DIR/scope_guard.py"
    chmod +x "$SKILL_DIR/recon.py"
    chmod +x "$SKILL_DIR/scope_guard.py"
    log "ClawSec files copied to $SKILL_DIR"
else
    err "SKILL.md not found next to setup_vm.sh. Run this script from the clawsec/ directory."
fi

# ── 6. Verify nmap works ───────────────────────────────────
log "Verifying nmap..."
if nmap --version &>/dev/null; then
    log "nmap OK: $(nmap --version | head -1)"
else
    err "nmap not working after install. Check apt output above."
fi

# ── 7. Verify scope guard ──────────────────────────────────
log "Testing scope guard..."
RESULT=$(python3 "$SKILL_DIR/scope_guard.py" "192.168.1.1" 2>/dev/null)
if [ "$RESULT" = "BLOCKED" ]; then
    log "Scope guard OK — private IPs correctly blocked"
else
    warn "Scope guard returned unexpected result for 192.168.1.1: $RESULT"
fi

# ── 8. HTB VPN note ───────────────────────────────────────
echo ""
warn "HTB NOTE: HackTheBox machines use 10.10.x.x (RFC1918)."
warn "Scope guard blocks private ranges by default."
warn "For HTB targets, run recon.py directly, bypassing scope_guard:"
warn "  python3 ~/.openclaw/skills/clawsec/recon.py --target 10.10.11.42 --scan quick"
echo ""

# ── Done ───────────────────────────────────────────────────
echo ""
echo -e "${GREEN}  ✓ ClawSec setup complete!${NC}"
echo ""
echo "  Next steps:"
echo "  1. Run: openclaw onboard"
echo "     → Set your Claude/OpenAI API key"
echo "     → Connect Telegram (create a bot via @BotFather)"
echo "  2. Start OpenClaw: openclaw start"
echo "  3. Message your Telegram bot: /clawsec <target>"
echo ""
echo "  🦞 Happy hacking (ethically). — Vertex Coders LLC"
echo ""
