# 💸 ClawSec — Cost & Usage Guide

> **⚠️ THIS IS NOT FREE. THIS IS NOT CHEAP. READ BEFORE DEPLOYING.**

ClawSec is built on top of the **Anthropic Claude API**, which charges per
token of input and output. Every `/clawsec <target>` command costs real money,
and uncontrolled deployment **will drain your wallet**.

This document is the survival guide.

---

## 🔥 The Honest Truth

During development we burned through **$30 USD in a single afternoon** doing
testing on a small set of targets. That's roughly:

- ~5 hours of active development
- ~30-50 recon runs
- A few prompts that hit the more expensive Sonnet/Opus tiers before we
  switched to Haiku

If you put this bot in a public Telegram group with 100 users running
`/clawsec` freely, **you can expect to lose $50-200 per day** with no
hard cap unless you configure one. Anthropic does not refund usage.

**This is not Anthropic's fault. This is the cost of LLM-powered tooling.**

---

## 📊 Real Cost Per Scan

Measured on Parrot OS, scanning `scanme.nmap.org` (2 open ports, ~500 input
tokens, ~400 output tokens):

| Model                       | Cost per scan | 100 scans | 1,000 scans |
|-----------------------------|---------------|-----------|-------------|
| Claude Opus 4.7             | ~$0.020       | $2.00     | $20.00      |
| Claude Sonnet 4.6           | ~$0.012       | $1.20     | $12.00      |
| **Claude Haiku 4.5 (default)** | **~$0.001**   | **$0.10** | **$1.00**   |
| Haiku 4.5 + prompt cache    | ~$0.0005      | $0.05     | $0.50       |

**ClawSec ships with Haiku 4.5 + prompt cache enabled by default.** Do not
override this without understanding the cost implications.

---

## 🛡️ How to Stay Solvent

### 1. Set a hard spend limit on Anthropic

This is **non-negotiable**. Go to:

```
https://console.anthropic.com/settings/limits
```

Set a monthly spend cap. Once you hit it, the API stops working until next
month. Better to hit a wall than to wake up $500 in the hole.

> **Note:** Anthropic also has account-level monthly usage tiers.
> Even if your spend limit is high, you may hit a tier limit and get locked
> out until the 1st of the next month at 00:00 UTC. There's no override.

### 2. Always use Haiku 4.5

The default `vic_bridge.py` uses `claude-haiku-4-5-20251001`. Only override
for deep analysis on a single target:

```bash
# Default (cheap):
python3 vic_bridge.py

# Override only when you really need Sonnet:
VIC_CLAUDE_MODEL=claude-sonnet-4-6 python3 vic_bridge.py
```

### 3. Limit max output tokens

Insights should be 2-3 sentences. Default cap is 450 tokens. Don't go higher.

```bash
VIC_MAX_TOKENS=300 python3 vic_bridge.py
```

### 4. Rate-limit your bot

If you expose `/clawsec` over Telegram, **do not let strangers run it**.
Options:

- **Whitelist**: only your `chat_id` can trigger scans.
- **Per-user limit**: max N scans per hour per user.
- **Approval flow**: bot asks "are you sure?" before running.

This is not implemented yet in v2.0. If you ship to a public bot, **build
this first** or you'll be donating to Anthropic.

### 5. Use `--no-vic` for cost-free recon

If you only need port data and don't need Claude's insight, skip the bridge:

```bash
python3 recon.py --target example.com --no-vic
```

This costs $0. nmap runs locally, JSON is generated, no API call is made.

### 6. Cache results, don't re-scan

If you already scanned `target.com` an hour ago, don't run it again. Read
the JSON from `/tmp/clawsec_results.json` or save the writeup that
`vic_bridge` wrote to `brain/datasets/raw_writeups/`.

---

## 💀 Cost Failure Modes (Real Stories)

### "I just left it running overnight"
The agent loop in VIC was hitting Claude every 2 seconds. **One night = $80.**
**Fix:** confirm the agent loop has a sleep delay and a target-change guard.

### "I pasted a 10,000-word writeup as the target"
The orchestrator's regex extracted text, sent it to Claude as the "target",
and Claude analyzed all of it. **One scan = $4.**
**Fix:** strict `extract_ip()` validation rejects strings >100 chars (already
applied in `main.py`).

### "I let my friend test it"
He ran 50 scans in 10 minutes to "see how fast it is". **$60 gone.**
**Fix:** rate limiting + per-user spend tracking. **Implement before sharing.**

### "I switched to Sonnet for one scan and forgot to switch back"
Default became Sonnet. Two weeks later, the bill was 10x higher than
expected. **Fix:** read your bills weekly. Set alerts at $5 and $20.

---

## 🧠 Final Wisdom

**ClawSec is a power tool. Treat it like a chainsaw, not a butter knife.**

- Always know which model you're using.
- Always know your spend cap.
- Never expose to untrusted users.
- Read your Anthropic dashboard weekly.
- If a scan returns garbage, **don't immediately re-run it** — fix the
  prompt or the input first.

LLM-powered tooling is incredible when you're aware of the costs. It's a
catastrophe when you treat it like grep.

---

## 📞 Cost Support

- Anthropic billing: https://console.anthropic.com/settings/billing
- Anthropic usage limits: https://console.anthropic.com/settings/limits
- ClawSec issues: https://github.com/Denisijcu/clawsec/issues

---

*Built by Vertex Coders LLC. Burned by ourselves first so you don't have to.*
🦞⚡
