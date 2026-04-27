#!/usr/bin/env python3
"""
ClawSec Phase 2 — Web Enumeration
Vertex Coders LLC

Deeper web recon than recon.py + web_discovery.py.
Designed to run AFTER feroxbuster (web_discovery.py) — it focuses on
identifying tech stack and known-vulnerable endpoints.

Tools:
  - whatweb (tech fingerprint)
  - nikto (vuln scanner, slow but valuable)
  - curl probes (robots.txt, sitemap.xml, .git/, .env, etc.)
  - nuclei (templates) if installed
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import urllib.request
import urllib.error
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from phase2 import session as sess


def _which(*candidates: str) -> str | None:
    for c in candidates:
        path = shutil.which(c)
        if path:
            return path
    return None


def _run(cmd: list[str], timeout: int = 120) -> tuple[int, str]:
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, errors="replace"
        )
        return out.returncode, (out.stdout + out.stderr)
    except subprocess.TimeoutExpired:
        return -1, f"[timeout after {timeout}s]"
    except FileNotFoundError:
        return -2, f"[binary not found]"
    except Exception as e:
        return -3, f"[error: {e}]"


def _save_raw(target: str, name: str, content: str) -> Path:
    out_dir = Path(os.path.expanduser(f"~/.clawsec/sessions/{target}/web"))
    out_dir.mkdir(parents=True, exist_ok=True)
    fp = out_dir / f"{name}.txt"
    fp.write_text(content)
    return fp


def _resolve_web_ports(ports: list[dict]) -> list[tuple[int, str]]:
    """Devuelve [(port, scheme)] para puertos HTTP/HTTPS abiertos."""
    web: list[tuple[int, str]] = []
    for p in ports:
        port = int(p.get("port", 0))
        service = (p.get("service", "") or "").lower()
        product = (p.get("product", "") or "").lower()
        is_https = (
            "https" in service or "ssl" in service or
            port in (443, 8443, 9443)
        )
        is_http = (
            "http" in service or
            port in (80, 8000, 8001, 8008, 8080, 8081, 8888, 5000, 9000, 9090)
        )
        if is_https:
            web.append((port, "https"))
        elif is_http:
            web.append((port, "http"))
    return web


# ── Probes ────────────────────────────────────────────────────────────────────

def probe_whatweb(target: str, port: int, scheme: str) -> dict:
    wb = _which("whatweb")
    if not wb:
        return {"status": "skipped", "msg": "whatweb not installed (apt install whatweb)"}

    url = f"{scheme}://{target}:{port}"
    code, out = _run([wb, "-a", "3", "--no-errors", "--color=never", url], timeout=45)
    _save_raw(target, f"whatweb_{port}", out)

    techs: list[str] = []
    for line in out.splitlines():
        # Cualquier identificador entre brackets en el output de whatweb
        for m in re.findall(r"([A-Z][\w\-]+)\[([^\]]+)\]", line):
            tech = f"{m[0]}={m[1]}"
            if tech not in techs:
                techs.append(tech)
        # Identificadores sin bracket
        for m in re.findall(r"\b(WordPress|Drupal|Joomla|Apache|nginx|Tomcat|IIS|Express|Flask|Django|PHP|Node\.js)\b", line):
            if m not in techs:
                techs.append(m)
    return {"status": "ok" if code == 0 else "partial", "techs": techs[:30],
            "raw_path": f"web/whatweb_{port}.txt"}


def probe_curl_sensitive(target: str, port: int, scheme: str) -> dict:
    """Probes muy livianos a paths comunes que filtran info."""
    sensitive_paths = [
        "/robots.txt",
        "/sitemap.xml",
        "/.git/config",
        "/.env",
        "/server-status",
        "/.well-known/security.txt",
        "/admin/",
        "/api/",
        "/swagger.json",
        "/swagger-ui/",
        "/actuator/health",
        "/actuator/env",
        "/wp-login.php",
        "/login",
        "/manager/html",   # Tomcat
    ]
    findings: list[dict] = []
    for path in sensitive_paths:
        url = f"{scheme}://{target}:{port}{path}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ClawSec/2.0"}, method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                status  = resp.status
                length  = int(resp.headers.get("Content-Length", "0") or "0")
                ctype   = resp.headers.get("Content-Type", "")
                body    = resp.read(2048).decode(errors="replace") if status < 400 else ""
        except urllib.error.HTTPError as e:
            status = e.code
            length = 0
            ctype  = ""
            body   = ""
        except Exception:
            continue

        if status in (200, 301, 302, 401, 403):
            findings.append({
                "path":         path,
                "status":       status,
                "content_type": ctype,
                "length":       length,
                "preview":      body[:200].replace("\n", " ") if body else "",
            })

    raw = "\n".join(f"{f['status']} {f['path']} ({f['length']}b {f['content_type']})" for f in findings)
    _save_raw(target, f"curl_sensitive_{port}", raw)
    return {"status": "ok", "findings": findings, "raw_path": f"web/curl_sensitive_{port}.txt"}


def probe_nuclei(target: str, port: int, scheme: str) -> dict:
    """nuclei con templates por defecto si está instalado."""
    nu = _which("nuclei")
    if not nu:
        return {"status": "skipped", "msg": "nuclei not installed"}

    url = f"{scheme}://{target}:{port}"
    code, out = _run([nu, "-target", url, "-silent", "-severity", "medium,high,critical",
                      "-no-color", "-disable-update-check"], timeout=180)
    _save_raw(target, f"nuclei_{port}", out)
    findings: list[str] = [l.strip() for l in out.splitlines() if l.strip().startswith("[")]
    return {"status": "ok" if code == 0 else "partial",
            "findings": findings[:50],
            "raw_path": f"web/nuclei_{port}.txt"}


# ── Orquestador ───────────────────────────────────────────────────────────────

def run(target: str, ports: list[dict] | None = None) -> dict:
    print(f"[web_enum] Starting web enumeration for {target}")
    if ports is None:
        # Cargar de session si no nos pasaron ports
        ports = sess.load(target)["phase1"]["ports"]

    web_ports = _resolve_web_ports(ports)
    if not web_ports:
        print("[web_enum] No HTTP/HTTPS ports detected, skipping.")
        return {"module": "web_enum", "target": target, "status": "no_web_ports"}

    print(f"[web_enum] Web ports detected: {web_ports}")
    results = {
        "module":    "web_enum",
        "target":    target,
        "per_port":  {},
    }

    for port, scheme in web_ports:
        port_results = {}
        print(f"[web_enum] Port {port} ({scheme}): whatweb...")
        port_results["whatweb"] = probe_whatweb(target, port, scheme)

        print(f"[web_enum] Port {port}: curl probes (robots, .git, swagger, etc.)...")
        port_results["sensitive"] = probe_curl_sensitive(target, port, scheme)

        print(f"[web_enum] Port {port}: nuclei (if available)...")
        port_results["nuclei"] = probe_nuclei(target, port, scheme)

        results["per_port"][port] = port_results

        # Update session: endpoints
        endpoints = [f for f in port_results["sensitive"].get("findings", [])]
        if endpoints:
            s = sess.load(target)
            for e in endpoints:
                entry = {"port": port, "scheme": scheme, **e}
                if entry not in s["phase2"]["endpoints"]:
                    s["phase2"]["endpoints"].append(entry)
            sess.save(target, s)

    sess.add_enum_run(target, "web_enum", "completed", results)

    # Resumen
    total_endpoints = sum(len(r["sensitive"].get("findings", [])) for r in results["per_port"].values())
    total_techs     = sum(len(r["whatweb"].get("techs", [])) for r in results["per_port"].values())
    total_nuclei    = sum(len(r["nuclei"].get("findings", [])) for r in results["per_port"].values())
    summary = {
        "ports_scanned":       len(web_ports),
        "tech_fingerprints":   total_techs,
        "sensitive_endpoints": total_endpoints,
        "nuclei_findings":     total_nuclei,
    }
    results["summary"] = summary
    print(f"[web_enum] ✅ Done. Tech: {total_techs} | "
          f"Endpoints: {total_endpoints} | Nuclei: {total_nuclei}")
    return results


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("target")
    p.add_argument("--port", type=int, action="append", help="Port to test (repeatable)")
    p.add_argument("--scheme", default="http")
    args = p.parse_args()

    if args.port:
        ports = [{"port": pt, "service": "http", "state": "open"} for pt in args.port]
    else:
        ports = [{"port": 80, "service": "http", "state": "open"}]
    out = run(args.target, ports)
    import json as _j
    print(_j.dumps(out.get("summary", {}), indent=2))
