#!/usr/bin/env python3
"""
ClawSec Web Discovery Module — v2.1
Vertex Coders LLC — 2026

Smart web discovery pipeline:
  nmap JSON → stack fingerprint → wordlist selection → feroxbuster → LLM analysis → Telegram report

LLM modes:
  --llm ollama   Local Gemma via Ollama (free, fast)
  --llm claude   Claude API (powerful, costs $)
  --llm auto     Ollama first, Claude fallback (default)

Usage:
  python3 web_discovery.py --target 10.10.11.42 --nmap-json /tmp/clawsec_results.json
  python3 web_discovery.py --target 10.10.11.42 --llm claude
  python3 web_discovery.py --target 10.10.11.42 --llm ollama
"""

import argparse
import json
import subprocess
import sys
import os
import datetime
import urllib.request
import urllib.error
from pathlib import Path

OUTPUT_FILE = Path("/tmp/clawsec_web_discovery.json")

# ── LLM Config ────────────────────────────────────────────────────────────────
# Ollama (local — free)
OLLAMA_URL   = os.environ.get("OLLAMA_URL",   "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "gemma3:1b")

# Claude (cloud — costs $)
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL   = "claude-sonnet-4-6"  # Sonnet es más barato que Opus

# ── Wordlists ─────────────────────────────────────────────────────────────────
WORDLISTS = {
    "flask":     "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "django":    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "express":   "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "rails":     "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "iis":       "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt",
    "aspnet":    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt",
    "apache":    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt",
    "nginx":     "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt",
    "tomcat":    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt",
    "wordpress": "/usr/share/seclists/Discovery/Web-Content/CMS/WordPress/wp-plugins.fuzz.txt",
    "unknown":   "/usr/share/seclists/Discovery/Web-Content/common.txt",
}
WORDLIST_FALLBACK = "/usr/share/seclists/Discovery/Web-Content/common.txt"

# ── Stack signatures ──────────────────────────────────────────────────────────
STACK_SIGNATURES = {
    "flask":     ["waitress", "werkzeug", "flask", "python"],
    "django":    ["django", "gunicorn", "daphne"],
    "express":   ["express", "node.js", "nodejs"],
    "rails":     ["rails", "phusion passenger", "ruby"],
    "iis":       ["microsoft-iis", "iis", "asp.net", "aspnet"],
    "aspnet":    ["asp.net", "aspnet", "microsoft"],
    "apache":    ["apache", "httpd"],
    "nginx":     ["nginx"],
    "tomcat":    ["tomcat", "coyote", "java"],
    "wordpress": ["wp-", "wordpress", "x-pingback"],
}

# ── Vertex Intelligence Prompt ────────────────────────────────────────────────
VERTEX_INTELLIGENCE_PROMPT = """You are a Senior Offensive Security Engineer working for Vertex Coders LLC.
Analyze ClawSec recon results on an authorized HackTheBox or pentest target.

Mission: Transform raw scan data into actionable attack intelligence.
Be concise, technical, direct. No defensive advice. Pure offensive analysis.

ANALYSIS CHAIN:
1. FINGERPRINT → Identify exact stack from headers, ports, services
2. MAP VULNS → Cross-reference with known attack patterns
3. PRIORITIZE → Rank by exploitability
4. SUGGEST → Give exact command to run next

STACK INTEL:
- Flask/Waitress: Check /static first (todo.txt, .env, config.txt). Test Prompt Injection if AI chatbot detected.
- IIS/ASP.NET: Check /web.config, /iisstart.htm. WinRM(5985)→Evil-WinRM. SMB(445)→enum4linux.
- Apache/Nginx: Check /robots.txt, /.env, /backup. Test SSTI if template engine detected.
- Tomcat: /manager/html default creds (tomcat/tomcat). Check CVE-2025-24813.
- Node.js: Check /.env, /api/docs, /swagger. JWT weak secrets.

DIRECTORY RULES:
- /admin, /dashboard → test default creds immediately
- /api, /v1, /v2 → enumerate endpoints, check IDOR
- /static, /assets → look for sensitive file exposure
- 403 with varied Content-Length → try X-Original-URL bypass
- 500 responses → injection point

OUTPUT FORMAT (Telegram, max 600 chars):
🎯 Target: [IP] | Stack: [stack]
🔥 Critical: [top finding]
📂 Paths: [interesting dirs]
⚡ Run this: [exact command]
🧠 Intel: [2-sentence analysis]
🦞 ClawSec v2.1 | Vertex Coders LLC"""


# ── Stack detection ───────────────────────────────────────────────────────────

def detect_stack_from_nmap(nmap_data: dict) -> tuple[str, list[int]]:
    http_ports = []
    detected_stack = "unknown"
    for p in nmap_data.get("ports", []):
        service = p.get("service", "").lower()
        version = (p.get("version", "") + " " + p.get("product", "")).lower()
        port    = p.get("port", 0)
        if service in ("http", "http-proxy", "https", "http-alt") or port in (80, 443, 8080, 8000, 8443, 8888):
            http_ports.append(port)
        combined = f"{service} {version}"
        for stack, sigs in STACK_SIGNATURES.items():
            if any(sig in combined for sig in sigs):
                detected_stack = stack
                break
    return detected_stack, http_ports


def detect_stack_from_headers(target: str, port: int) -> str:
    try:
        url = f"http://{target}:{port}"
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", "Mozilla/5.0 (ClawSec/2.1)")
        with urllib.request.urlopen(req, timeout=5) as resp:
            combined = (resp.headers.get("Server", "") + " " + resp.headers.get("X-Powered-By", "")).lower()
            for stack, sigs in STACK_SIGNATURES.items():
                if any(sig in combined for sig in sigs):
                    print(f"[web_discovery] Stack from headers: {stack}", file=sys.stderr)
                    return stack
    except Exception as e:
        print(f"[web_discovery] Header probe :{port} failed — {e}", file=sys.stderr)
    return "unknown"


def get_wordlist(stack: str) -> str:
    wl = WORDLISTS.get(stack, WORDLISTS["unknown"])
    if not Path(wl).exists():
        print(f"[web_discovery] Wordlist not found: {wl} — falling back", file=sys.stderr)
        if Path(WORDLIST_FALLBACK).exists():
            return WORDLIST_FALLBACK
        fallback = Path("/tmp/clawsec_wordlist.txt")
        fallback.write_text("\n".join([
            "admin","login","static","api","config","backup","uploads",
            "files","assets","images","js","css","app","dashboard","panel",
            "todo.txt",".env","config.txt","robots.txt","sitemap.xml",
            "index.php","index.html","index.aspx","default.aspx",
        ]))
        return str(fallback)
    return wl


# ── Feroxbuster ───────────────────────────────────────────────────────────────

def run_feroxbuster(target: str, port: int, wordlist: str, stack: str) -> dict:
    url         = f"http://{target}:{port}"
    output_file = f"/tmp/ferox_{target.replace('.','_')}_{port}.json"
    ext_map = {
        "flask":   "txt,py,cfg,env",
        "django":  "txt,py,cfg,env",
        "iis":     "aspx,asp,txt,config,bak",
        "aspnet":  "aspx,asp,txt,config,bak",
        "apache":  "php,txt,html,bak,env",
        "nginx":   "php,txt,html,bak,env",
        "tomcat":  "jsp,do,action,txt",
        "unknown": "txt,php,html,aspx,env,config,bak",
    }
    exts = ext_map.get(stack, ext_map["unknown"])
    cmd = [
        "feroxbuster", "--url", url,
        "--wordlist", wordlist,
        "--status-codes", "200,201,204,301,302,307,401,403,500",
        "--output", output_file, "--json", "--no-state", "--silent",
        "--threads", "30", "--timeout", "7", "--extract-links",
        "--depth", "1",
        "--extensions", exts,
    ]
    print(f"[web_discovery] Fuzzing {url} [{stack}] ext={exts}", file=sys.stderr)
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return {"error": "feroxbuster timed out", "findings": []}
    except FileNotFoundError:
        return {"error": "feroxbuster not installed. Run: sudo apt install feroxbuster", "findings": []}

    findings = []
    if Path(output_file).exists():
        with open(output_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if entry.get("type") == "response":
                        findings.append({
                            "url":    entry.get("url", ""),
                            "status": entry.get("status", 0),
                            "length": entry.get("content_length", 0),
                            "words":  entry.get("word_count", 0),
                        })
                except json.JSONDecodeError:
                    pass

    priority = {200: 0, 201: 1, 204: 2, 403: 3, 301: 4, 302: 5, 500: 6}
    findings.sort(key=lambda x: priority.get(x["status"], 99))
    return {"findings": findings[:50], "total": len(findings)}


# ── LLM: Ollama (local — free) ────────────────────────────────────────────────

def analyze_with_ollama(prompt: str) -> str:
    payload = json.dumps({
        "model":  OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
    }).encode()
    req = urllib.request.Request(
        OLLAMA_URL, data=payload,
        headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())
            return data.get("response", "No response from Ollama")
    except urllib.error.URLError:
        raise ConnectionError("Ollama offline — run: ollama serve")
    except Exception as e:
        raise RuntimeError(f"Ollama error: {e}")


# ── LLM: Claude API (cloud — powerful) ───────────────────────────────────────

def analyze_with_claude(prompt: str) -> str:
    if not ANTHROPIC_API_KEY:
        raise ValueError("ANTHROPIC_API_KEY not set — export ANTHROPIC_API_KEY=sk-ant-...")
    payload = json.dumps({
        "model":      ANTHROPIC_MODEL,
        "max_tokens": 800,
        "system":     VERTEX_INTELLIGENCE_PROMPT,
        "messages":   [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages", data=payload,
        headers={
            "Content-Type":      "application/json",
            "x-api-key":         ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
        }, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
            return data["content"][0]["text"]
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"Claude API error {e.code}: {e.read().decode()[:200]}")
    except Exception as e:
        raise RuntimeError(f"Claude error: {e}")


# ── LLM dispatcher ────────────────────────────────────────────────────────────

def build_prompt(target: str, stack: str, nmap_data: dict, ferox_data: dict) -> str:
    ports_summary = [
        f"  {p['port']}/tcp {p['service']} {p.get('product','')} {p.get('version','')} [{p.get('risk','?')}]"
        for p in nmap_data.get("ports", [])
    ]
    findings_summary = [
        f"  [{f['status']}] {f['url']} (size:{f['length']})"
        for f in ferox_data.get("findings", [])[:20]
    ]
    return f"""TARGET: {target}
STACK: {stack}

NMAP PORTS:
{chr(10).join(ports_summary) or "  No port data"}

WEB DISCOVERY (feroxbuster):
{chr(10).join(findings_summary) or "  No paths found"}
Total paths: {ferox_data.get('total', 0)}

Give me the Vertex Intelligence report and exact next command."""


def analyze_with_llm(target: str, stack: str, nmap_data: dict, ferox_data: dict, mode: str) -> str:
    """
    Dispatch to the right LLM based on mode:
      ollama → local Gemma (free)
      claude → Claude API (powerful, costs $)
      auto   → try Ollama first, fallback to Claude
    """
    prompt = build_prompt(target, stack, nmap_data, ferox_data)
    full_prompt = f"{VERTEX_INTELLIGENCE_PROMPT}\n\n{prompt}" if mode == "ollama" else prompt

    if mode == "ollama":
        print("[web_discovery] 🤖 Using Ollama (local Gemma — free)", file=sys.stderr)
        try:
            return analyze_with_ollama(full_prompt)
        except Exception as e:
            return f"⚠️ Ollama failed: {e}\nRun: ollama pull {OLLAMA_MODEL}"

    elif mode == "claude":
        print("[web_discovery] 🧠 Using Claude API (powerful mode)", file=sys.stderr)
        try:
            return analyze_with_claude(prompt)
        except Exception as e:
            return f"⚠️ Claude failed: {e}"

    else:  # auto
        print("[web_discovery] ⚡ Auto mode — trying Ollama first...", file=sys.stderr)
        try:
            result = analyze_with_ollama(full_prompt)
            print("[web_discovery] ✅ Ollama responded", file=sys.stderr)
            return result
        except Exception as e:
            print(f"[web_discovery] ⚠️ Ollama failed ({e}) — falling back to Claude...", file=sys.stderr)
            try:
                return analyze_with_claude(prompt)
            except Exception as e2:
                return f"⚠️ Both LLMs failed.\nOllama: {e}\nClaude: {e2}"


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="ClawSec Smart Web Discovery v2.1")
    parser.add_argument("--target",    required=True)
    parser.add_argument("--nmap-json", default="/tmp/clawsec_results.json")
    parser.add_argument("--port",      type=int, default=0)
    parser.add_argument("--stack",     default="")
    parser.add_argument("--wordlist",  default="")
    parser.add_argument("--no-llm",    action="store_true", help="Skip LLM analysis")
    parser.add_argument("--llm",       default="auto",
                        choices=["auto", "ollama", "claude"],
                        help="LLM backend: auto (default), ollama (free/local), claude (powerful/$)")
    args = parser.parse_args()

    print(f"\n[web_discovery] 🦞 ClawSec Smart Discovery v2.1 | Vertex Coders LLC", file=sys.stderr)
    print(f"[web_discovery] Target: {args.target} | LLM: {args.llm}", file=sys.stderr)

    # Load nmap data
    nmap_data = {"ports": []}
    nmap_path = Path(args.nmap_json)
    if nmap_path.exists():
        try:
            raw = json.loads(nmap_path.read_text())
            nmap_data = raw.get("nmap", {"ports": []})
            print(f"[web_discovery] Loaded nmap: {len(nmap_data.get('ports',[]))} ports", file=sys.stderr)
        except Exception as e:
            print(f"[web_discovery] nmap JSON error: {e}", file=sys.stderr)

    # Detect stack
    stack, http_ports = detect_stack_from_nmap(nmap_data)
    if args.stack:
        stack = args.stack.lower()
    if args.port:
        http_ports = [args.port]
    if not http_ports:
        http_ports = [80, 8080]
    if stack == "unknown":
        for port in http_ports:
            detected = detect_stack_from_headers(args.target, port)
            if detected != "unknown":
                stack = detected
                break

    print(f"[web_discovery] Stack: {stack} | Ports: {http_ports}", file=sys.stderr)

    # Select wordlist
    wordlist = args.wordlist if args.wordlist else get_wordlist(stack)
    print(f"[web_discovery] Wordlist: {wordlist}", file=sys.stderr)

    # Run feroxbuster
    all_findings = []
    ferox_results = {}
    for port in http_ports[:3]:
        print(f"\n[web_discovery] Fuzzing port {port}...", file=sys.stderr)
        result = run_feroxbuster(args.target, port, wordlist, stack)
        if "error" in result:
            print(f"[web_discovery] ⚠️ {result['error']}", file=sys.stderr)
        else:
            findings = result.get("findings", [])
            all_findings.extend(findings)
            ferox_results[str(port)] = result
            print(f"[web_discovery] Port {port}: {len(findings)} paths found", file=sys.stderr)

    combined_ferox = {"findings": all_findings[:50], "total": len(all_findings), "by_port": ferox_results}

    # LLM analysis
    if not args.no_llm:
        print(f"\n[web_discovery] Running Vertex Intelligence ({args.llm})...", file=sys.stderr)
        llm_report = analyze_with_llm(args.target, stack, nmap_data, combined_ferox, args.llm)
    else:
        top = [f"  [{f['status']}] {f['url']}" for f in all_findings[:10]]
        llm_report = f"🎯 {args.target} | {stack}\n" + ("\n".join(top) or "  No paths found")

    # Save
    output = {
        "meta": {
            "target": args.target, "stack": stack, "ports": http_ports,
            "wordlist": wordlist, "llm_mode": args.llm,
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "tool": "ClawSec Web Discovery v2.1 by Vertex Coders LLC",
        },
        "feroxbuster": combined_ferox,
        "llm_analysis": llm_report,
    }
    OUTPUT_FILE.write_text(json.dumps(output, indent=2))
    print(f"\n[web_discovery] Results saved to {OUTPUT_FILE}", file=sys.stderr)
    print("\n" + "─" * 70)
    print(llm_report)
    print("─" * 70)
    print(f"DONE | stack={stack} | paths={len(all_findings)} | llm={args.llm} | output={OUTPUT_FILE}")


if __name__ == "__main__":
    main()
