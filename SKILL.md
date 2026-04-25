---
name: clawsec
description: >
  Offensive reconnaissance assistant for authorized security assessments.
  Use when the user asks to scan, recon, enumerate, or assess a target host or domain.
  Triggers on: 'scan', 'recon', 'enumerate', 'nmap', 'ports', 'subdomains', 'whois',
  'attack surface', 'pentest', 'hackthebox', 'ctf target'.
  NOT for: general web browsing, coding help, or any target the user has not explicitly
  authorized in writing.
metadata:
  openclaw:
    emoji: "🦞🔍"
    requires:
      bins:
        - python3
        - nmap
    install:
      - id: apt
        kind: apt
        packages:
          - nmap
          - python3
          - python3-pip
        label: "Install nmap + python3 (apt)"
---

# ClawSec — Offensive Recon Skill

Built by **Vertex Coders LLC** for the DEV Community OpenClaw Challenge 2026.

## Purpose

ClawSec turns your OpenClaw instance into a personal offensive recon assistant.
It runs structured reconnaissance on authorized targets and returns an AI-analyzed
security report directly in your chat channel (Telegram, Discord, web, etc.).

**IMPORTANT — Authorized use only.**
Only run ClawSec against targets you own or have explicit written permission to test.
Unauthorized scanning is illegal. ClawSec's scope guard blocks RFC1918, loopback,
and cloud metadata endpoints by default.

---

## Workflow

Follow these steps in order. Do not skip scope validation.

### Step 1 — Parse the user request

Extract from the user message:
- `target`: IP address or domain (e.g., `10.10.11.42` or `example.com`)
- `scan_type`: one of `quick`, `full`, `stealth` (default: `quick`)
- `modules`: subset of `[ports, whois, subdomains]` (default: `[ports, whois]`)
- `allow_lab`: true if the user says "htb", "hackthebox", "offsec", or uses `--allow-lab`
- `wordlist`: optional custom subdomain wordlist path

If `target` is missing, ask:
"What is the target IP or domain? Please confirm you are authorized to scan it."

### Step 2 — Scope validation

Run scope guard before ANY scan:

```bash
python3 ~/.openclaw/skills/clawsec/scope_guard.py <target>
# For HTB/lab/CTF targets (10.10.x.x, 10.129.x.x, 10.11.x.x):
python3 ~/.openclaw/skills/clawsec/scope_guard.py --allow-lab <target>
# For custom internal targets the user has authorized:
python3 ~/.openclaw/skills/clawsec/scope_guard.py --allowlist ~/.clawsec/allowlist.txt <target>
```

- If the script prints `BLOCKED`, tell the user why and stop.
  Example: "❌ Target blocked by scope guard — IP is in a blocked private/reserved range. Use `--allow-lab` only for HTB/Offsec ranges, or add the target to your allowlist at `~/.clawsec/allowlist.txt`."
- If the script prints `ALLOWED`, proceed to Step 3.

Metadata endpoints (169.254.169.254, `metadata.google.internal`) and loopback
are **always** blocked — `--allow-lab` and allowlist cannot override them.

### Step 3 — Execute recon modules

```bash
python3 ~/.openclaw/skills/clawsec/recon.py \
    --target <target> \
    --scan <scan_type> \
    --modules <modules> \
    [--wordlist <path>]
```

Wait for completion. The script writes a JSON report to `/tmp/clawsec_results.json`.

Timeouts: 240s for `quick`/`stealth`, 600s for `full`.

### Step 4 — Analyze results with AI

Read `/tmp/clawsec_results.json` and produce a structured security report.

Fields available per port: `port`, `protocol`, `service`, `product`, `version`,
`extrainfo`, `cpe`, `scripts`, `risk`, `risk_reason`.

Produce:

1. **Executive summary** — 2-3 sentences on overall attack surface
2. **Open ports & services** — table with port, service, version, risk level (Critical/High/Medium/Low/Info) and the reason
3. **Key findings** — bullet list of notable discoveries (EOL services, CVE-prone versions, unusual ports, interesting nmap scripts output)
4. **Recommended next steps** — what a pentester would investigate next (for CTF/authorized use)
5. **WHOIS / DNS summary** — registrar, nameservers, discovered subdomains if applicable

Sort ports by risk level (Critical → Info).

### Step 5 — Format and send report

Format the final report in Markdown and send it to the active channel.
Template:

```
🦞 **ClawSec Report** | Vertex Coders LLC
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
**Target:** <target>
**Scan type:** <scan_type>
**Timestamp:** <UTC timestamp>

📋 **Executive Summary**
<2-3 sentence summary>

🔓 **Open Ports & Services**
| Port | Service | Version | Risk | Reason |
|------|---------|---------|------|--------|
| ...  | ...     | ...     | ...  | ...    |

🎯 **Key Findings**
- <finding 1>
- <finding 2>

🧭 **Recommended Next Steps**
- <step 1>
- <step 2>

📎 **Whois / DNS**
Registrar: <registrar>
Nameservers: <ns1>, <ns2>
Subdomains found: <count>
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️ For authorized use only | github.com/vertex-coders/clawsec
```

Channel-specific formatting:
- **Discord / WhatsApp:** replace the Markdown table with a bulleted list
  (some channels don't render tables well).
- **Telegram:** Markdown tables render fine; use as-is.

---

## Slash command

Users can invoke ClawSec directly with:

```
/clawsec <target> [quick|full|stealth] [--htb] [--modules ports,whois,subdomains]
```

Examples:
- `/clawsec scanme.nmap.org` — quick scan on nmap's public test host
- `/clawsec example.com full` — full scan with all ports
- `/clawsec 10.10.11.42 quick --htb` — HTB machine (bypasses RFC1918 block for lab ranges only)
- `/clawsec example.com stealth --modules ports,whois,subdomains` — slow SYN scan with full module set

When the user passes `--htb` or mentions HackTheBox/Offsec, pass `--allow-lab`
to `scope_guard.py`.

---

## Error handling

- **nmap not installed:** "❌ nmap not found. Run: `sudo apt install nmap`"
- **whois not installed:** "❌ whois not found. Run: `sudo apt install whois`"
- **Scan timeout (>240s quick / >600s full):** return partial results with a timeout warning.
- **Target unreachable:** "⚠️ Target did not respond. Verify the IP/domain and your network connection."
- **Scope guard BLOCKED:** surface the reason from stderr, do not run recon.
- Never dump raw error stack traces to the user — summarize in plain English.

---

## Files

| File | Purpose |
|------|---------|
| `scope_guard.py` | Target validation (RFC1918, metadata, allowlist, `--allow-lab`) |
| `recon.py` | nmap (XML parsed) + whois (TLD fallback) + subdomain enumeration |
| `tests/test_scope_guard.py` | 19 unit tests for scope validation |


| `tests/test_risk.py` | 11 unit tests for version-based risk scoring |
| `setup_vm.sh` | One-shot installer for Kali / Debian / Ubuntu |

Current engine version: **0.2.0**


---
name: clawsec
description: >
  Assists in offensive reconnaissance and web discovery for authorized security assessments.
  Automatically identifies services, evaluates risk, and performs directory fuzzing on web targets.
triggers: ['scan', 'recon', 'enumerate', 'nmap', 'fuzz', 'feroxbuster', 'htb', 'ctf', 'what do you find on']
metadata:
  openclaw:
    emoji: "🦞🔍"
    version: "2.0.0"
    requires:
      bins: ["python3", "nmap", "feroxbuster", "whois"]
    install:
      - id: apt
        kind: apt
        packages: ["nmap", "python3", "feroxbuster", "whois", "seclists"]
        label: "Install Vertex Recon Stack (Apt)"

---

# ClawSec v2.0 — Offensive Recon + Smart Web Discovery

Built by Vertex Coders LLC.

**IMPORTANT — Authorized use only.**

---

## Workflow

### Phase 1 — Recon

**Step 1 — Parse request**
Extract: target, scan_type (quick/full/stealth), modules, lab_mode (HTB/CTF)

**Step 2 — Scope validation**
```bash
python3 ~/.openclaw/skills/clawsec/scope_guard.py <target>
# HTB ranges:
python3 ~/.openclaw/skills/clawsec/scope_guard.py --allow-lab <target>
```
BLOCKED → stop. ALLOWED → proceed.

**Step 3 — Recon**
```bash
python3 ~/.openclaw/skills/clawsec/recon.py --target <target> --scan <scan_type> --modules <modules>
```

### Phase 2 — Smart Web Discovery (auto-triggered on HTTP ports)

**Step 4 — Web discovery**
```bash
python3 ~/.openclaw/skills/clawsec/web_discovery.py \
  --target <target> \
  --nmap-json /tmp/clawsec_results.json
```

**Step 5 — Combined report to channel**
```
🦞 ClawSec v2.0 Report | Vertex Coders LLC
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Target: <target> | <timestamp>
📋 RECON: <ports summary>
🔓 PORTS: <port table>
📂 WEB DISCOVERY: <stack + paths>
🎯 VERTEX INTELLIGENCE: <LLM next step>
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️ Authorized use only | github.com/Denisijcu/clawsec
```

## Slash commands
```
/clawsec <target>              # quick scan + web discovery
/clawsec <target> full         # all ports
/clawsec <target> --htb        # HTB lab mode
/clawsec <target> --no-web     # skip web discovery
/discover <target> [port]      # web discovery only
```
