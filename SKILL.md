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

Built by Vertex Coders LLC for the DEV Community OpenClaw Challenge 2026.

## Purpose

ClawSec turns your OpenClaw instance into a personal offensive recon assistant.
It runs structured reconnaissance on authorized targets and returns an AI-analyzed
security report directly in your chat channel (Telegram, Discord, etc.).

**IMPORTANT — Authorized use only.**
Only run ClawSec against targets you own or have explicit written permission to test.
Unauthorized scanning is illegal. ClawSec will refuse private IP ranges and
non-authorized targets when scope guard is enabled.

---

## Workflow

Follow these steps in order. Do not skip scope validation.

### Step 1 — Parse the user request

Extract from the user message:
- `target`: IP address or domain (e.g., `10.10.11.42` or `example.com`)
- `scan_type`: one of `quick`, `full`, `stealth` (default: `quick`)
- `modules`: list from `[ports, whois, subdomains]` (default: `[ports, whois]`)

If `target` is missing, ask the user: "What is the target IP or domain? Please confirm you are authorized to scan it."

### Step 2 — Scope validation

Run scope guard before ANY scan:

```bash
python3 ~/.openclaw/skills/clawsec/scope_guard.py <target>
```

- If scope guard returns `BLOCKED`, tell the user: "❌ Target blocked by scope guard. ClawSec only runs against authorized targets. Private IP ranges and localhost are always blocked."
- If scope guard returns `ALLOWED`, proceed to Step 3.

### Step 3 — Execute recon modules

Run the recon script with the validated target:

```bash
python3 ~/.openclaw/skills/clawsec/recon.py --target <target> --scan <scan_type> --modules <modules>
```

Wait for completion. The script outputs a JSON file at `/tmp/clawsec_results.json`.

### Step 4 — Analyze results with AI

Read `/tmp/clawsec_results.json` and produce a structured security report.

Analyze the raw findings and generate:

1. **Executive summary** — 2-3 sentences on overall attack surface
2. **Open ports & services** — table with port, service, version, risk level (Critical/High/Medium/Low/Info)
3. **Key findings** — bullet list of notable discoveries (unusual ports, outdated services, interesting headers)
4. **Recommended next steps** — what a pentester would investigate next (for CTF/authorized use)
5. **Raw data summary** — whois registrar, nameservers, discovered subdomains if applicable

### Step 5 — Format and send report

Format the final report in Markdown and send it to the active channel.
Use this template:

```
🦞 **ClawSec Report** | Vertex Coders LLC
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
**Target:** <target>
**Scan type:** <scan_type>
**Timestamp:** <UTC timestamp>

📋 **Executive Summary**
<2-3 sentence summary>

🔓 **Open Ports & Services**
| Port | Service | Version | Risk |
|------|---------|---------|------|
| ...  | ...     | ...     | ...  |

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

---

## Slash command

Users can invoke ClawSec directly with:

```
/clawsec <target> [quick|full|stealth]
```

Examples:
- `/clawsec 10.10.11.42` — quick scan on HTB machine
- `/clawsec example.com full` — full scan with subdomains
- `/clawsec 10.10.11.100 stealth` — slower, lower-noise scan

---

## Error handling

- If nmap is not installed: "❌ nmap not found. Run: `sudo apt install nmap`"
- If scan times out (>120s): return partial results with a timeout warning
- If target is unreachable: "⚠️ Target did not respond. Verify the IP/domain and your network connection."
- Never expose raw error stack traces to the user — summarize in plain English
