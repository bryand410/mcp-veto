"""Live proof against a real third-party MCP server.

Runs @modelcontextprotocol/server-filesystem behind the gate and shows, in
order: a read that passes, a write that is held, the approval URL, the write
that executes only after the click, and a write that is refused and never
happens.

    python demo/live.py --auto-approve 3
"""

from __future__ import annotations

import argparse
import json
import queue
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT / "demo" / "workspace"


def _resolve(command: str) -> str:
    """Windows ships npx as a shell script; CreateProcess needs the .cmd shim."""
    found = shutil.which(command)
    if found:
        return found
    for suffix in (".cmd", ".exe", ".bat"):
        found = shutil.which(command + suffix)
        if found:
            return found
    raise SystemExit(f"command not found: {command}")


SERVER = [_resolve("npx"), "-y", "@modelcontextprotocol/server-filesystem@2.2.0", str(WORKSPACE)]


class Client:
    def __init__(self, target: list[str], timeout: float) -> None:
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "mcp_veto", "run", "--timeout", str(timeout), "--", *target],
            cwd=str(ROOT),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.out: queue.Queue[str | None] = queue.Queue()
        self.err: queue.Queue[str | None] = queue.Queue()
        threading.Thread(target=self._pump, args=(self.proc.stdout, self.out), daemon=True).start()
        threading.Thread(target=self._pump, args=(self.proc.stderr, self.err), daemon=True).start()
        self._id = 0

    @staticmethod
    def _pump(stream, sink) -> None:
        for line in stream:
            sink.put(line)
        sink.put(None)

    def _write(self, msg: dict) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def send(self, method: str, params: dict | None = None) -> int:
        self._id += 1
        self._write({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}})
        return self._id

    def notify(self, method: str, params: dict | None = None) -> None:
        self._write({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def recv(self, timeout: float = 90.0) -> dict | None:
        try:
            line = self.out.get(timeout=timeout)
        except queue.Empty:
            return None
        return json.loads(line) if line else None

    def url(self, timeout: float = 30.0) -> str:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                line = self.err.get(timeout=max(0.1, deadline - time.monotonic()))
            except queue.Empty:
                break
            if line and "/a/" in line:
                return next(w for w in line.split() if w.startswith("http"))
        raise SystemExit("no approval URL was announced")

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def answer(url: str, decision: str) -> None:
    body = urllib.parse.urlencode({"decision": decision}).encode()
    urllib.request.urlopen(urllib.request.Request(url, data=body), timeout=10).read()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--auto-approve",
        type=float,
        default=None,
        help="click after N seconds instead of waiting for a human",
    )
    ap.add_argument("--timeout", type=float, default=120.0)
    args = ap.parse_args()

    WORKSPACE.mkdir(parents=True, exist_ok=True)
    (WORKSPACE / "notes.md").write_text("readable without asking\n", encoding="utf-8")
    for leftover in ("written-after-approval.txt", "never-written.txt"):
        (WORKSPACE / leftover).unlink(missing_ok=True)

    client = Client(SERVER, args.timeout)
    try:
        print("1. initialize")
        client.send(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "demo", "version": "0"},
            },
        )
        init = client.recv()
        print("   server:", init["result"]["serverInfo"]["name"], init["result"]["serverInfo"]["version"])

        print("2. tools/list")
        client.notify("notifications/initialized")
        client.send("tools/list", {})
        tools = client.recv()["result"]["tools"]
        print(f"   {len(tools)} tools announced")

        print("3. read_text_file - must pass untouched")
        client.send(
            "tools/call", {"name": "read_text_file", "arguments": {"path": str(WORKSPACE / "notes.md")}}
        )
        read = client.recv()
        print("   result:", read["result"]["content"][0]["text"].strip())

        print("4. write_file - must be held")
        target = WORKSPACE / "written-after-approval.txt"
        client.send(
            "tools/call",
            {"name": "write_file", "arguments": {"path": str(target), "content": "approved by a human\n"}},
        )
        held_at = time.monotonic()
        url = client.url()
        print("   approval URL:", url)
        time.sleep(0.5)
        print("   file on disk now?", target.exists(), "(expected False)")
        assert not target.exists()

        if args.auto_approve is None:
            print("\n   >>> open the URL and click Approuver. Waiting...\n")
        else:
            time.sleep(args.auto_approve)
            answer(url, "approve")
            print(f"   approved after {time.monotonic() - held_at:.1f}s")

        reply = client.recv()
        print("   reply:", json.dumps(reply.get("result", reply.get("error")))[:110])
        print(
            "   file on disk now?",
            target.exists(),
            "->",
            target.read_text().strip() if target.exists() else "",
        )

        print("5. write_file - refused")
        never = WORKSPACE / "never-written.txt"
        client.send(
            "tools/call",
            {"name": "write_file", "arguments": {"path": str(never), "content": "should not exist\n"}},
        )
        url = client.url()
        if args.auto_approve is None:
            print("\n   >>> open the URL and click Refuser. Waiting...\n")
        else:
            time.sleep(args.auto_approve)
            answer(url, "deny")
        reply = client.recv()
        print("   reply:", json.dumps(reply.get("error"))[:130])
        print("   file on disk now?", never.exists(), "(expected False)")
        return 0 if not never.exists() and target.exists() else 1
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
