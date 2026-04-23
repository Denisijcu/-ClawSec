# 🦞 ClawSec

**Offensive recon assistant for OpenClaw.**
Built by [Vertex Coders LLC](https://github.com/vertex-coders) for the
DEV Community **OpenClaw Challenge 2026**.

ClawSec turns your OpenClaw agent into an on-demand reconnaissance operator.
You chat with your agent on Telegram/Discord/web, it runs structured scans on
authorized targets, and it sends you back an AI-analyzed attack-surface report —
all without leaving the chat.

> ⚠️ **Authorized use only.**
> Only run ClawSec against targets you own or have explicit written permission
> to test. Unauthorized port scanning is illegal in most jurisdictions.
> The built-in scope guard blocks RFC1918, loopback, and cloud metadata
> endpoints by default.

---

## ✨ Features

- 🛡️ **Scope guard** — refuses private IPs, loopback, link-local, multicast,
  and AWS/GCP/Azure metadata endpoints out of the box
- 🔍 **Nmap integration** — three profiles (`quick`, `full`, `stealth`),
  XML-parsed output with CPE + service + script data preserved
- 📇 **WHOIS with TLD fallback** — retries with the authoritative registrar
  server when the default whois query returns malformed data (fixes `.org`,
  `.io`, `.dev`, `.ai`, etc.)
- 🌐 **Subdomain bruteforce** — default 34-word list, or point it at your own
  wordlist with `--wordlist path/to/list.txt`
- 🎯 **Version-aware risk scoring** — flags known-bad releases (OpenSSH ≤6.6,
  Apache ≤2.4.29, PHP 5.x, vsftpd 2.3.4 backdoor, Samba 3.x, …) as **Critical**
  with a human-readable reason
- 🧪 **HTB / Offsec / CTF mode** — `--allow-lab` opens only the well-known lab
  ranges (10.10/16, 10.129/16, 10.11/16) without disabling the rest of the
  scope guard
- ✅ **Tested** — 30 unit tests covering scope validation and risk scoring
- 📦 **Single-file scripts** — no heavy framework; pure Python stdlib + nmap

---

## 🚀 Quickstart

### 1. Install

Clone the repo on your VM (Kali / Debian / Ubuntu) and run the setup script:

```bash
git clone https://github.com/vertex-coders/clawsec.git
cd clawsec
bash setup_vm.sh
```

The script will:

1. Install `nmap`, `whois`, `python3`, Node.js 20, and `pnpm`
2. Install OpenClaw (if not already present)
3. Copy the skill files into `~/.openclaw/skills/clawsec/`
4. Seed an empty allowlist at `~/.clawsec/allowlist.txt`
5. Run the self-tests

### 2. Onboard OpenClaw

```bash
openclaw onboard          # set API key + connect a channel (Telegram / Discord / web)
openclaw gateway start    # start the daemon
```

### 3. Scan something

From any connected channel:

```
/clawsec scanme.nmap.org
/clawsec example.com full
/clawsec 10.10.11.42 quick --htb
```

Or run the scripts directly:

```bash
python3 ~/.openclaw/skills/clawsec/scope_guard.py scanme.nmap.org
python3 ~/.openclaw/skills/clawsec/recon.py --target scanme.nmap.org --scan quick
cat /tmp/clawsec_results.json
```

---

## 📋 Example — scanning `scanme.nmap.org`

`scanme.nmap.org` is Nmap's public test host; the Nmap project explicitly
authorizes scanning it.

```
$ python3 recon.py --target scanme.nmap.org --scan quick --modules ports,whois
[recon] Running nmap (quick): nmap -sV -T4 --open -F -oX - scanme.nmap.org
[recon] Running whois on scanme.nmap.org
[recon]   retrying whois via whois.publicinterestregistry.org
[recon] Results saved to /tmp/clawsec_results.json
DONE | ports=2 | critical=2 | high=0 | subdomains=0 | output=/tmp/clawsec_results.json
```

Parsed results (trimmed):

```json
{
  "meta": {
    "target": "scanme.nmap.org",
    "scan_type": "quick",
    "timestamp": "2026-04-23T21:36:00Z",
    "version": "0.2.0"
  },
  "nmap": {
    "host_state": "up",
    "hostnames": ["scanme.nmap.org"],
    "ports": [
      {
        "port": 22,
        "service": "ssh",
        "product": "OpenSSH",
        "version": "6.6.1p1 Ubuntu 2ubuntu2.13",
        "cpe": ["cpe:/a:openbsd:openssh:6.6.1p1"],
        "risk": "Critical",
        "risk_reason": "OpenSSH <= 6.6 (CVE-laden, EOL)"
      },
      {
        "port": 80,
        "service": "http",
        "product": "Apache httpd",
        "version": "2.4.7",
        "cpe": ["cpe:/a:apache:http_server:2.4.7"],
        "risk": "Critical",
        "risk_reason": "Apache httpd <= 2.4.29"
      }
    ]
  }
}
```

The OpenClaw agent then reads this JSON and sends a human-readable report back
to your chat channel.

---

## 🏗️ Architecture

```
┌──────────────────┐    /clawsec <target>    ┌────────────────┐
│ Telegram/Discord │ ──────────────────────▶ │   OpenClaw     │
└──────────────────┘                         │  (SKILL.md)    │
                                             └───────┬────────┘
                                                     │
                                       ┌─────────────┴─────────────┐
                                       ▼                           ▼
                              ┌─────────────────┐        ┌──────────────────┐
                              │ scope_guard.py  │        │    recon.py      │
                              │ (allow/block)   │ ──▶    │ nmap+whois+subs  │
                              └─────────────────┘        └────────┬─────────┘
                                                                  │ JSON
                                                                  ▼
                                                    /tmp/clawsec_results.json
                                                                  │
                                                                  ▼
                                                      AI report → chat channel
```

---

## 📁 Repository layout

| Path | Purpose |
|------|---------|
| `SKILL.md` | OpenClaw skill manifest + agent workflow |
| `scope_guard.py` | Target validation (RFC1918, metadata, allowlist, `--allow-lab`) |
| `recon.py` | Nmap (XML) + WHOIS (TLD fallback) + subdomain enumeration |
| `setup_vm.sh` | One-shot installer for Kali / Debian / Ubuntu |
| `tests/test_scope_guard.py` | 19 unit tests for scope validation |
| `tests/test_risk.py` | 11 unit tests for version-based risk scoring |
| `LICENSE` | MIT |

---

## 🧪 Running the tests

```bash
python3 tests/test_scope_guard.py
python3 tests/test_risk.py
# or with pytest:
python3 -m pytest tests/ -v
```

All 30 tests should pass:

```
Ran 19 tests in 0.021s — OK   # scope_guard
Ran 11 tests in 0.001s — OK   # risk_level
```

---

## 🧭 Scope-guard rules

Default behavior when you run `scope_guard.py <target>`:

| Target                                   | Result     |
|------------------------------------------|------------|
| Public IP / public domain                | ✅ ALLOWED |
| `192.168.x.x`, `10.x.x.x`, `172.16–31.x` | ❌ BLOCKED (RFC1918) |
| `127.x.x.x`                              | ❌ BLOCKED (loopback) |
| `169.254.169.254`                        | ❌ BLOCKED (cloud metadata) |
| `localhost`, `*.local`, `*.internal`     | ❌ BLOCKED |
| `metadata.google.internal`               | ❌ BLOCKED |

### Opening HTB / Offsec / CTF ranges safely

```bash
python3 scope_guard.py --allow-lab 10.10.11.42      # HTB classic
python3 scope_guard.py --allow-lab 10.129.14.22     # HTB Enterprise
python3 scope_guard.py --allow-lab 10.11.1.5        # OSCP lab
```

`--allow-lab` opens **only** `10.10.0.0/16`, `10.129.0.0/16`, `10.11.0.0/16`.
Other RFC1918 addresses, loopback, and metadata endpoints remain blocked.

### User allowlist

For one-off internal targets the user has explicit permission to test:

```bash
echo "192.168.50.10" >> ~/.clawsec/allowlist.txt
echo "internal.corp.example.com" >> ~/.clawsec/allowlist.txt
python3 scope_guard.py --allowlist ~/.clawsec/allowlist.txt 192.168.50.10
```

Metadata endpoints and loopback cannot be allowlisted — those are hardcoded
as always-blocked.

---

## 🎛️ Nmap scan profiles

| Profile   | Flags                                | Use case                         |
|-----------|--------------------------------------|----------------------------------|
| `quick`   | `-sV -T4 --open -F`                  | Default. Top 100 ports, ~10–30 s |
| `full`    | `-sV -sC -T3 --open -p-`             | All 65535 ports + default scripts |
| `stealth` | `-sS -sV -T2 --open -F`              | SYN scan, slower, less noise      |

Timeouts: 240 s for `quick`/`stealth`, 600 s for `full`.

---

## 🧠 Risk scoring

`recon.py` assigns a risk level to every open port using three signals in order:

1. **Known-bad version patterns** → **Critical** with a reason
   (e.g. `OpenSSH <= 6.6`, `vsftpd 2.3.4 backdoor`)
2. **Port category fallback** → High (RDP, SMB, FTP, MSSQL, Redis, Mongo…),
   Medium (SSH, HTTP, SMTP…), Low (HTTPS…)
3. **Everything else** → Info

Risk patterns are easy to extend — edit `CRITICAL_VERSION_PATTERNS` in `recon.py`.

---

## 🤝 Contributing

Built by **Vertex Coders LLC**. PRs welcome, especially:

- More CVE/EOL version patterns
- Additional TLD whois servers
- Bigger bundled subdomain wordlists
- Extra scan profiles (UDP, OS-fingerprint, etc.)

---

## 📜 License

MIT — see [`LICENSE`](./LICENSE).

---

🦞 *Happy hacking (ethically). — Vertex Coders LLC*
