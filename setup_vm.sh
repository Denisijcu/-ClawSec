#!/usr/bin/env bash
# ============================================================
# ClawSec VM Setup Script
# Vertex Coders LLC — 2026
# Supports: Kali Rolling, Debian 12+, Ubuntu 22.04+
# Run as:   bash setup_vm.sh
# ============================================================

set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
info() { echo -e "${BLUE}[i]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }

echo ""
echo "  🦞 ClawSec Setup — Vertex Coders LLC"
echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── 0. Detect distro ───────────────────────────────────────
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO_ID="${ID:-unknown}"
    DISTRO_NAME="${PRETTY_NAME:-$DISTRO_ID}"
else
    DISTRO_ID="unknown"
    DISTRO_NAME="unknown"
fi
info "Detected: ${DISTRO_NAME}"

case "$DISTRO_ID" in
    kali|debian|ubuntu|linuxmint|pop)
        info "apt-based distro — proceeding"
        ;;
    *)
        warn "Untested distro (${DISTRO_ID}). Will attempt apt anyway."
        ;;
esac

# Pick sudo or direct (root VMs like Kali often run as root)
if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
    info "Running as root — skipping sudo"
else
    SUDO="sudo"
fi

# ── 1. System deps ─────────────────────────────────────────
log "Updating apt index..."
$SUDO apt update -qq

log "Installing dependencies (nmap, whois, python3, git)..."
$SUDO apt install -y -qq \
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
    curl -fsSL https://deb.nodesource.com/setup_20.x | $SUDO -E bash - -q
    $SUDO apt install -y -qq nodejs
else
    NODE_VER=$(node --version)
    log "Node.js already installed: $NODE_VER"
fi

# ── 3. pnpm (OpenClaw prefers pnpm) ───────────────────────
if ! command -v pnpm &>/dev/null; then
    log "Installing pnpm..."
    $SUDO npm install -g pnpm --silent
else
    log "pnpm already installed: $(pnpm --version)"
fi

# ── 4. OpenClaw ────────────────────────────────────────────
if [ ! -d "$HOME/.openclaw" ]; then
    log "Installing OpenClaw..."
    curl -fsSL https://openclaw.ai/install.sh | bash
    warn "OpenClaw installed. Run 'openclaw onboard' to configure your API key + channel."
else
    log "OpenClaw already present at ~/.openclaw"
fi

# ── 5. ClawSec skill ───────────────────────────────────────
SKILL_DIR="$HOME/.openclaw/skills/clawsec"
log "Installing ClawSec skill to $SKILL_DIR ..."
mkdir -p "$SKILL_DIR" "$HOME/.clawsec"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -f "$SCRIPT_DIR/SKILL.md" ]; then
    err "SKILL.md not found next to setup_vm.sh. Run this script from the clawsec/ directory."
fi

cp "$SCRIPT_DIR/SKILL.md"       "$SKILL_DIR/SKILL.md"
cp "$SCRIPT_DIR/recon.py"       "$SKILL_DIR/recon.py"
cp "$SCRIPT_DIR/scope_guard.py" "$SKILL_DIR/scope_guard.py"
chmod +x "$SKILL_DIR/recon.py" "$SKILL_DIR/scope_guard.py"
log "Skill files copied."

# Seed an empty allowlist the user can edit
if [ ! -f "$HOME/.clawsec/allowlist.txt" ]; then
    cat > "$HOME/.clawsec/allowlist.txt" <<'EOF'
# ClawSec user allowlist
# One target per line (IP or domain). Lines starting with # are ignored.
# Targets listed here bypass the RFC1918 / private-range block in scope_guard.
# Always-blocked ranges (loopback, AWS metadata) can never be allowlisted.
#
# Example:
# 192.168.50.10
# internal.example.com
EOF
    log "Created empty allowlist at ~/.clawsec/allowlist.txt"
fi

# ── 6. Verify nmap works ───────────────────────────────────
log "Verifying nmap..."
if nmap --version &>/dev/null; then
    log "nmap OK: $(nmap --version | head -1)"
else
    err "nmap not working after install. Check apt output above."
fi

# ── 7. Run tests (non-fatal) ───────────────────────────────
if [ -d "$SCRIPT_DIR/tests" ]; then
    log "Running self-tests..."
    if python3 "$SCRIPT_DIR/tests/test_scope_guard.py" -v 2>&1 | tail -1 | grep -q "OK"; then
        log "scope_guard tests: OK"
    else
        warn "scope_guard tests reported failures — check manually with:"
        warn "  python3 $SCRIPT_DIR/tests/test_scope_guard.py"
    fi
    if python3 "$SCRIPT_DIR/tests/test_risk.py" -v 2>&1 | tail -1 | grep -q "OK"; then
        log "risk_level tests: OK"
    else
        warn "risk_level tests reported failures"
    fi
fi

# ── 8. Quick functional check ──────────────────────────────
log "Testing scope guard against a private IP..."
RESULT=$(python3 "$SKILL_DIR/scope_guard.py" "192.168.1.1" 2>/dev/null || true)
if [ "$RESULT" = "BLOCKED" ]; then
    log "Scope guard correctly blocks RFC1918"
else
    warn "Scope guard returned unexpected result for 192.168.1.1: $RESULT"
fi

# ── 9. Lab/HTB note ───────────────────────────────────────
echo ""
info "HackTheBox / Offsec / CTF labs:"
info "  Use the --allow-lab flag (NOT disabling the scope guard entirely):"
info "    python3 $SKILL_DIR/scope_guard.py --allow-lab 10.10.11.42"
info "  Or add specific targets to ~/.clawsec/allowlist.txt"
echo ""

# ── Done ───────────────────────────────────────────────────
echo ""
echo -e "${GREEN}  ✓ ClawSec setup complete!${NC}"
echo ""
echo "  Next steps:"
echo "  1. Run: openclaw onboard"
echo "     → Set your Claude/OpenAI API key"
echo "     → Connect Telegram (create a bot via @BotFather)"
echo "  2. Start OpenClaw: openclaw gateway start"
echo "  3. Message your channel: /clawsec scanme.nmap.org"
echo ""
echo "  🦞 Happy hacking (ethically). — Vertex Coders LLC"
echo ""
