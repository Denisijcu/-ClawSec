# 🦞 ClawSec v3.0

[![tests](https://github.com/Denisijcu/clawsec/actions/workflows/tests.yml/badge.svg)](https://github.com/Denisijcu/clawsec/actions/workflows/tests.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![version](https://img.shields.io/badge/version-3.0.0-red.svg)]()

**AI-powered offensive recon & exploitation assistant.**
Built by [Vertex Coders LLC](https://vertexcoders.com) for the DEV Community **OpenClaw Challenge 2026**.

ClawSec is not just another recon script — it's a **co-pilot** for authorized
penetration testing. It runs structured reconnaissance, deep enumeration, and
asks an LLM advisor for the next exploitation step, all while persisting
session context across runs.

```
/clawsec 10.10.11.42 --htb
        ↓
Phase 1:  Recon (nmap + WHOIS + subdomains + risk scoring)
        ↓
Phase 2:  Stack-aware enumeration (SMB, Web, AD, Linux/Windows post)
        ↓
VIC Advisor (xAI / Groq / Claude / Ollama) → "Here's your next step + command"
        ↓
Telegram / Discord / Web report with actionable next moves
```

> ⚠️ **Authorized use only.**
> Only run ClawSec against targets you own or have explicit written permission
> to test (HackTheBox, TryHackMe, scanme.nmap.org, signed engagements).

---

## ✨ What's New in v3.0

- 🚀 **Phase 2: Enumeration & Exploitation Guidance** — clawSec now goes
  beyond recon. Detects stack (SMB, Web, AD), runs deeper enumeration
  modules, and asks an LLM advisor for next-step exploitation plan.
- 🧠 **Multi-backend AI** — `xai` (Grok 4.1 Fast, default), `groq`
  (Llama 3.3 70B, free tier), `claude` (Anthropic Haiku 4.5), `ollama`
  (local models). Switch via `VIC_BACKEND` env var. Auto-fallback chain.
- 💾 **Persistent sessions** — `~/.clawsec/sessions/<target>.json` stores
  shares, users, credentials, dead ends, shells, advisor history.
  ClawSec remembers across runs — that's what makes it a co-pilot.
- 💸 **Cost-aware design** — Default backend (xAI Grok) is ~$0.0005/scan.
  See [`COST_AND_USAGE.md`](./COST_AND_USAGE.md) for spending guardrails.
- 🐚 **Shell handler** — Reverse shell payload generator (Linux + Windows),
  listener commands, shell tracking per target.

### What's still here from v2.0

- 🌐 Smart Web Discovery (stack-aware feroxbuster)
- 🛡️ Scope Guard (RFC1918, metadata blocking, lab allowlist)
- 🦞 OpenClaw skill integration (Telegram/Discord/Web)

---

## 🏗️ Architecture

```
                  /clawsec <target>
                         │
                ┌────────▼────────┐
                │  scope_guard    │  RFC1918 / metadata / allowlist
                └────────┬────────┘
                         │ ALLOWED
                         ▼
        ┌────────────────────────────────────┐
        │           PHASE 1 — Recon          │
        │  recon.py:                         │
        │    nmap (XML) + risk scoring       │
        │    whois + TLD fallback            │
        │    subdomain enumeration           │
        │  web_discovery.py:                 │
        │    stack fingerprint + feroxbuster │
        └────────────────┬───────────────────┘
                         │ JSON results
                         ▼
        ┌────────────────────────────────────┐
        │       PHASE 2 — Enumeration        │
        │  enum_dispatcher.py (stack detect) │
        │    ├── smb_enum (139, 445, 135)    │
        │    ├── web_enum (80, 443, ...)     │
        │    ├── ad_enum  (88, 389)          │
        │    ├── linux_enum_post  (post-RCE) │
        │    └── windows_enum_post (post-RCE)│
        └────────────────┬───────────────────┘
                         │ session.json updated
                         ▼
        ┌────────────────────────────────────┐
        │     VIC ADVISOR (LLM-powered)      │
        │   exploit_advisor.py:              │
        │   reads full session → asks LLM    │
        │   returns: priority, command,      │
        │   expected outcome, fallback       │
        └────────────────┬───────────────────┘
                         ▼
                ┌────────────────┐
                │  vic_bridge.py │  ← multi-backend
                ├────────────────┤
                │  xai (default) │
                │  groq          │
                │  claude        │
                │  ollama        │
                └────────────────┘
                         │
                         ▼
                Report → channel
```

---

## 📁 Repository Layout

```
clawsec/
├── SKILL.md                    OpenClaw skill manifest + workflow
├── scope_guard.py              Target validation (RFC1918, allowlist, --allow-lab)
├── recon.py                    Phase 1: nmap + whois + subdomain enum
├── web_discovery.py            Smart web discovery (feroxbuster + IA)
├── vic_bridge.py               Legacy v2 single-backend bridge (kept)
├── vic_bridge_v3.py            v3 multi-backend bridge ← USE THIS
├── vic_hook.py                 Reference snippet for recon hook
├── clawsec_telegram.sh         Standalone runner (no gateway)
├── COST_AND_USAGE.md           Real cost analysis & guardrails
├── phase2/
│   ├── session.py              Persistent session state per target
│   ├── enum_dispatcher.py      Stack detection → module routing
│   ├── exploit_advisor.py      LLM-powered next-step advisor
│   ├── phase2_runner.py        Phase 2 CLI orchestrator
│   ├── shell_handler.py        Revshell gen + shell tracking
│   └── modules/
│       ├── smb_enum.py         nmap NSE / smbclient / enum4linux-ng / netexec
│       ├── web_enum.py         whatweb / curl probes / nuclei
│       ├── ad_enum.py          ldapsearch / kerbrute / GetNPUsers
│       ├── linux_enum_post.py  POSIX privesc enum (post-RCE)
│       └── windows_enum_post.py PowerShell privesc enum (post-RCE)
├── tests/
│   ├── test_scope_guard.py     19 tests for scope validation
│   └── test_risk.py            11 tests for risk scoring
├── wordlists/
│   └── subdomains-top200.txt   Bundled 200-entry list
├── setup_vm.sh                 Kali / Parrot / Ubuntu installer
└── CHANGELOG.md                Release notes
```

---

## 🚀 Quickstart

### 1. Clone and install dependencies

```bash
git clone https://github.com/Denisijcu/clawsec.git
cd clawsec
bash setup_vm.sh

# Phase 2 toolchain (Kali/Parrot)
sudo apt install -y nmap whatweb nuclei nikto enum4linux-ng smbclient \
                    nbtscan rpcclient hydra ldap-utils impacket-scripts \
                    feroxbuster seclists
sudo curl -sL https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64 \
       -o /usr/local/bin/kerbrute && sudo chmod +x /usr/local/bin/kerbrute

# Python deps for the bridge
pip install fastapi uvicorn anthropic openai python-dotenv
```

### 2. Configure backend keys

Create `/opt/vertex-intelligence-core/.env` (or the workdir of the bridge):

```bash
# Recommended: xAI (Grok) — cheap, fast, good quality
XAI_API_KEY=xai-...

# Optional fallbacks:
GROQ_API_KEY=gsk_...           # free tier, fast
ANTHROPIC_API_KEY=sk-ant-...   # premium quality, paid
```

### 3. Start the VIC Bridge

```bash
# Default backend = xAI Grok
python3 vic_bridge_v3.py

# Override backend:
VIC_BACKEND=groq    python3 vic_bridge_v3.py
VIC_BACKEND=claude  python3 vic_bridge_v3.py
VIC_BACKEND=ollama  python3 vic_bridge_v3.py
VIC_BACKEND=auto    python3 vic_bridge_v3.py    # tries xai → groq → claude → ollama
```

Bridge listens on `localhost:5100`.

### 4. Run a scan

```bash
# Phase 1 only (fast recon)
python3 recon.py --target 10.10.11.42 --scan quick --modules ports,whois

# Phase 2 (deep enum + advisor)
python3 phase2/phase2_runner.py 10.10.11.42

# Plan-only (see what would run, no execution)
python3 phase2/phase2_runner.py 10.10.11.42 --plan-only

# Specific module(s)
python3 phase2/phase2_runner.py 10.10.11.42 --only smb_enum,ad_enum
```

### 5. From Telegram

Once OpenClaw is running with the skill registered:

```
/clawsec scanme.nmap.org           # quick recon + advisor
/clawsec 10.10.11.42 --htb         # HTB lab, full pipeline
/discover 10.10.11.42 8080 flask   # web discovery only
```

---

## 🧠 The Advisor

After phase 2 enumeration, `exploit_advisor.py` builds a complete summary of
the session (open ports, shares, users, creds, endpoints, dead ends) and
asks the LLM:

> *Based on this context, what's the highest-value exploitation step?*

Returns structured output:

```
🥇 TOP PRIORITY:   Active Directory user 'svc_sql' has SPN registered
💡 WHY:            Kerberoasting yields offline-crackable hash
💻 NEXT COMMAND:   impacket-GetUserSPNs -request -dc-ip 10.10.11.42 corp.local/guest:guest
✅ EXPECTED:       $krb5tgs$23$... hash for offline cracking with hashcat -m 13100
🔁 IF BLOCKED:     Try AS-REP roasting on accounts with DONT_REQUIRE_PREAUTH
🥈 PRIORITY 2:     SMB share BACKUP$ has READ access — check for credentials in config files
```

This is what makes ClawSec a **co-pilot, not a script**: it knows what you've
already tried, what didn't work, and what credentials you've recovered.

---

## 🛡️ Scope Guard

| Target | Default | With `--allow-lab` |
|--------|---------|---------------------|
| Public IP / domain | ✅ allowed | ✅ allowed |
| `10.x.x.x`, `192.168.x.x` | ❌ blocked | ❌ blocked (unless lab range) |
| `127.x.x.x` (loopback) | ❌ always blocked | ❌ always blocked |
| `169.254.169.254` (cloud metadata) | ❌ always blocked | ❌ always blocked |
| `10.10.0.0/16` (HTB VPN) | ❌ blocked | ✅ allowed |
| `10.129.0.0/16` (HTB Enterprise) | ❌ blocked | ✅ allowed |
| `10.11.0.0/16` (Offsec/OSCP) | ❌ blocked | ✅ allowed |
| `172.20.0.0/16` (Vertex internal lab) | ❌ blocked | ✅ allowed |

Custom targets: add to `~/.clawsec/allowlist.txt` (one per line).

---

## 💾 Session State

Every target gets a JSON file at `~/.clawsec/sessions/<target>.json`
that grows with every run:

```json
{
  "target": "10.10.11.42",
  "phase1": {
    "ports": [...],
    "stacks": ["smb", "web", "ldap"]
  },
  "phase2": {
    "shares": [{"share": "IPC$", "access": "READ"}],
    "users": ["administrator", "svc_sql", "j.smith"],
    "credentials": [{"user": "svc_sql", "kind": "kerberos-tgs", "secret": "$krb5tgs..."}],
    "endpoints": [{"port": 80, "path": "/admin/", "status": 401}]
  },
  "shells": [{"id": 1, "user": "www-data", "method": "rce", "history": [...]}],
  "dead_ends": ["EternalBlue not vulnerable", "anonymous SMB blocked"],
  "vic_history": [...]
}
```

This is what an LLM advisor needs to give **good** advice. No tool that lacks
this context can match clawSec.

---

## 🐚 Reverse Shell Generator

```bash
# Generate Linux payloads
python3 phase2/shell_handler.py 10.10.11.42 revshell --lhost 10.10.14.5 --lport 4444 --os linux

# Generate Windows payloads
python3 phase2/shell_handler.py 10.10.11.42 revshell --lhost 10.10.14.5 --lport 4444 --os windows

# Listener commands for your attacker box
python3 phase2/shell_handler.py 10.10.11.42 listener --lport 4444

# Register a shell you obtained
python3 phase2/shell_handler.py 10.10.11.42 add --user www-data --method "RCE via Apache 2.4.49"
```

---

## 🧪 Tests

```bash
python3 tests/test_scope_guard.py   # 19 tests
python3 tests/test_risk.py          # 11 tests
```

CI on Python 3.11 / 3.12 / 3.13 via GitHub Actions.

---

## 💸 Costs

ClawSec uses external LLM APIs by default. **Read [`COST_AND_USAGE.md`](./COST_AND_USAGE.md)
before deploying** — uncontrolled bots will drain your wallet.

| Backend | Cost per scan (est.) |
|---------|----------------------|
| **xAI Grok 4.1 Fast** | ~$0.0005 |
| Groq Llama 3.3 70B (free tier) | $0 (rate-limited) |
| Claude Haiku 4.5 + cache | ~$0.001 |
| Claude Sonnet 4.6 | ~$0.012 |
| Ollama local (Gemma3 1B) | $0 (slow on CPU) |

ClawSec defaults to **xAI Grok** for the best price/quality/speed balance.

---

## 🗺️ Roadmap

**v3.0 (current)** ✅
- [x] Phase 2 enumeration modules
- [x] Multi-backend AI bridge
- [x] Persistent session state
- [x] LLM-powered advisor with full context
- [x] Reverse shell generator
- [x] Linux + Windows post-exploitation enum

**v3.1 (next)**
- [ ] BloodHound integration (graph-based AD attack paths)
- [ ] Auto-CVE PoC retrieval (searchsploit + GitHub PoCs)
- [ ] Hash cracking dispatcher (hashcat / john)
- [ ] Pivoting helper (chisel / sshuttle / ligolo-ng config gen)

**v4.0 (vision)**
- [ ] Auto-pilot mode (with safety gates)
- [ ] HTB API integration (auto flag submission)
- [ ] Cooperative multi-target (one bot, many shells)

---

## ⚠️ Legal & Ethics

ClawSec is for **authorized** penetration testing, HackTheBox/CTF labs, and
security research on systems you own. Unauthorized scanning is illegal.

Vertex Coders LLC operating principles:
- ✅ Ethics first, always
- 🚫 No revenge mode
- 🛡️ Don't break what works
- 💰 Money is real (cost-aware design)
- 📝 Document the painful parts

---

## 👾 Built by

**[Vertex Coders LLC](https://vertexcoders.com)** — Miami, FL
AI Automation & Cybersecurity | HTB Creator Program

*"From recon to root — one chat command at a time."* 🦞⚡
