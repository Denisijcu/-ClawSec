# 🦞 ClawSec v2.0

[![tests](https://github.com/Denisijcu/clawsec/actions/workflows/tests.yml/badge.svg)](https://github.com/Denisijcu/clawsec/actions/workflows/tests.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![version](https://img.shields.io/badge/version-2.0.0-red.svg)]()

**Offensive recon assistant for OpenClaw — now with Smart Web Discovery and VIC Bridge.**
Built by [Vertex Coders LLC](https://github.com/vertex-coders) for the DEV Community **OpenClaw Challenge 2026**.

ClawSec turns your OpenClaw agent into an on-demand reconnaissance operator.
Type `/clawsec 10.10.11.42 --htb` in Telegram, and you get:
- Full port scan with CVE-aware risk scoring
- Automatic web discovery with stack-aware fuzzing
- AI-analyzed attack surface report
- VIC Brain insight from your local Gemma 3-4B

> ⚠️ **Authorized use only.**
> Only run ClawSec against targets you own or have explicit written permission to test.

---

## ✨ What's New in v2.0

- 🌐 **Smart Web Discovery** — `web_discovery.py` auto-detects stack and runs `feroxbuster` with the right wordlist
- 🧠 **VIC Bridge** — connects ClawSec to your local Vertex Intelligence Core (Gemma 3-4B via LM Studio)
- 🎯 **Vertex Intelligence Prompt** — LLM acts as Senior Pentester, not a generic chatbot
- 🔬 **Stack fingerprinting** — Flask/Waitress, IIS/ASP.NET, Apache, Nginx, Tomcat, WordPress
- ⚡ **HTB `--allow-lab` flag** — opens lab ranges without disabling scope guard

---

## 🏗️ Architecture

```
┌─────────────────┐    /clawsec <target>    ┌────────────────┐
│ Telegram/Discord│ ──────────────────────▶ │   OpenClaw     │
└─────────────────┘                         │  (SKILL.md)    │
                                            └───────┬────────┘
                                                    │
                                    ┌───────────────┴───────────────┐
                                    ▼                               ▼
                           ┌─────────────────┐           ┌──────────────────┐
                           │ scope_guard.py  │           │    recon.py      │
                           │ (allow/block)   │──▶        │ nmap+whois+subs  │
                           └─────────────────┘           └────────┬─────────┘
                                                                  │ JSON
                                                                  ▼
                                                        web_discovery.py
                                                        (feroxbuster + LLM)
                                                                  │
                                                                  ▼
                                                          vic_bridge.py
                                                        (Gemma 3-4B RAG)
                                                                  │
                                                                  ▼
                                                    AI report + VIC insight
                                                         → chat channel
```

---

## 📁 Repository Layout

| File | Purpose |
|------|---------|
| `SKILL.md` | OpenClaw skill manifest + agent workflow |
| `scope_guard.py` | Target validation (RFC1918, metadata, allowlist, `--allow-lab`) |
| `recon.py` | Nmap (XML) + WHOIS (TLD fallback) + subdomain enumeration |
| `web_discovery.py` | Stack fingerprint + feroxbuster + Vertex Intelligence analysis |
| `vic_bridge.py` | FastAPI endpoint — ClawSec ↔ Vertex Intelligence Core |
| `vic_hook.py` | Hook code to integrate into recon.py |
| `setup_vm.sh` | One-shot installer for Kali / Parrot / Ubuntu |
| `tests/test_scope_guard.py` | 19 unit tests for scope validation |
| `tests/test_risk.py` | 11 unit tests for version-based risk scoring |
| `wordlists/subdomains-top200.txt` | Bundled 200-entry subdomain wordlist |
| `CHANGELOG.md` | Release notes |

---

## 🚀 Quickstart

### 1. Clone and setup

```bash
git clone https://github.com/Denisijcu/clawsec.git
cd clawsec
bash setup_vm.sh
```

### 2. Install new dependencies (v2.0)

```bash
sudo apt install feroxbuster seclists -y
pip install fastapi uvicorn
```

### 3. Onboard OpenClaw

```bash
openclaw onboard    # API key + Telegram bot
openclaw gateway start
```

### 4. Start VIC Bridge (on your HP Omen)

```bash
# In your VIC project directory
python3 vic_bridge.py
# Bridge listens on localhost:5100
```

### 5. Scan

```bash
# From Telegram
/clawsec scanme.nmap.org
/clawsec 10.10.11.42 quick --htb
/discover 10.10.11.42 8080 flask

# Direct CLI
python3 recon.py --target scanme.nmap.org --scan quick
python3 web_discovery.py --target scanme.nmap.org --nmap-json /tmp/clawsec_results.json
```

---

## 🧠 Web Discovery — How It Works

```
nmap detects HTTP port
        ↓
Stack fingerprint (headers + nmap data)
        ↓
    Flask/Waitress  →  common.txt + .txt,.py,.cfg extensions
    IIS/ASP.NET     →  IIS.fuzz.txt + .aspx,.asp,.config extensions
    Apache/Nginx    →  raft-medium-directories + .php,.html,.bak
    Tomcat          →  tomcat.txt + .jsp,.do,.action
        ↓
feroxbuster (30 threads, 7s timeout)
        ↓
Filter: 200, 301, 403 (size-varied), 500
        ↓
Vertex Intelligence Prompt → LLM analysis
        ↓
Telegram report + VIC Bridge ingest
```

---

## 🔗 VIC Bridge Integration

The VIC Bridge connects ClawSec to your local **Vertex Intelligence Core** (Gemma 3-4B via LM Studio).

### Start the bridge

```bash
# In your VIC project root
python3 vic_bridge.py
```

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/vic/status` | Check Gemma + bridge status |
| POST | `/vic/ingest` | Receive ClawSec JSON → RAG insight |

### What happens automatically

1. ClawSec finishes recon
2. `recon.py` POSTs results to `localhost:5100/vic/ingest`
3. VIC Bridge saves writeup to `brain/datasets/raw_writeups/`
4. Gemma 3-4B analyzes with your HTB knowledge base
5. Insight returns to ClawSec → appended to Telegram report

### Non-blocking design

If VIC is offline, ClawSec continues normally — the bridge is optional.

---

## 🛡️ Scope Guard

| Target | Result |
|--------|--------|
| Public IP / domain | ✅ ALLOWED |
| `10.x.x.x`, `192.168.x.x`, `172.16-31.x` | ❌ BLOCKED (RFC1918) |
| `127.x.x.x` | ❌ BLOCKED (loopback) |
| `169.254.169.254` | ❌ BLOCKED (cloud metadata) |
| `10.10.0.0/16`, `10.129.0.0/16`, `10.11.0.0/16` | ✅ ALLOWED with `--allow-lab` |

```bash
python3 scope_guard.py scanme.nmap.org          # public target
python3 scope_guard.py --allow-lab 10.10.11.42  # HTB machine
```

---

## 🧪 Tests

```bash
python3 tests/test_scope_guard.py   # 19 tests
python3 tests/test_risk.py          # 11 tests

Ran 30 tests — OK
```

CI runs on Python 3.11 / 3.12 / 3.13 via GitHub Actions.

---

## 🗺️ Roadmap

**v2.0 (current)**
- ✅ Smart web discovery with stack-aware fuzzing
- ✅ VIC Bridge (ClawSec ↔ Gemma 3-4B)
- ✅ Vertex Intelligence Prompt

**v3.0 (planned)**
- Celery + Redis async task queue
- LangChain ReAct tool chaining
- Auto tool chain: port 80 → ffuf, SMB → enum4linux
- PDF report export from Telegram
- HTB API integration for flag submission

---

## ⚠️ Legal & Ethics

ClawSec is built for authorized penetration testing, HackTheBox/CTF environments,
and security research on systems you own. Unauthorized scanning is illegal.

---

## 👾 Built by

**[Vertex Coders LLC](https://vertexcoders.com)** — Miami, FL
AI Automation & Cybersecurity | HTB Creator Program

*"Automate the tedious recon. Focus on the exploitation."* 🦞
