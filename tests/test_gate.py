"""Tests for the gate. The last one runs two real processes end to end.

The rule this file follows: a test that only inspects the decision object
proves the gate is a filter. The integration test proves it is a gate, because
it checks the file on disk does not exist while the call is pending.
"""

from __future__ import annotations

import json
import queue
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mcp_veto.approval import Approver
from mcp_veto.gate import Gate
from mcp_veto.policy import Policy

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "stdio_server.py"


def call(name: str, arguments: dict, **params: object) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments, **params},
    }


def make_gate(answer: bool | None = True, asked: list | None = None, **kwargs: object) -> Gate:
    asked = asked if asked is not None else []

    def ask(pending):
        asked.append(pending)
        return answer

    return Gate(
        policy=Policy.default(),
        approver=Approver(secret=b"k" * 32),
        ask=ask,
        server_name="fixture",
        **kwargs,
    )


def test_a_read_passes_without_asking() -> None:
    asked: list = []
    gate = make_gate(asked=asked)
    decision = gate.decide(call("read_file", {"path": "a.txt"}))
    assert decision.forward is True
    assert asked == []
    assert decision.request["params"]["name"] == "read_file"


def test_a_write_is_stopped_until_it_is_approved() -> None:
    asked: list = []
    gate = make_gate(asked=asked)
    decision = gate.decide(call("write_file", {"path": "a.txt", "content": "hi"}))

    assert len(asked) == 1
    pending = asked[0]
    assert pending.tool == "write_file"
    assert pending.arguments == {"path": "a.txt", "content": "hi"}
    assert pending.digest  # bound to the exact arguments
    assert decision.forward is True


def test_a_refused_call_never_leaves_the_gate() -> None:
    asked: list = []
    gate = make_gate(answer=False, asked=asked)
    decision = gate.decide(call("write_file", {"path": "a.txt", "content": "hi"}))

    assert decision.forward is False
    assert decision.reply["id"] == 7
    assert decision.reply["error"]["code"] == -32001
    assert "refused" in decision.reply["error"]["message"].lower()


def test_a_timeout_is_not_a_refusal_and_says_so() -> None:
    gate = make_gate(answer=None)
    decision = gate.decide(call("write_file", {"path": "a.txt", "content": "hi"}))

    assert decision.forward is False
    assert decision.reply["error"]["code"] == -32002
    assert "timed out" in decision.reply["error"]["message"].lower()


def test_an_approval_token_is_bound_to_one_exact_call() -> None:
    """A yes for 'write a.txt' must not authorise 'write b.txt'."""
    asked: list = []
    gate = make_gate(asked=asked)
    original = call("write_file", {"path": "a.txt", "content": "hi"})
    token = gate.approver.grant(
        gate.approver.pending("fixture", "write_file", original["params"]["arguments"])
    )

    replay = call("write_file", {"path": "b.txt", "content": "hi"}, _meta={"veto_token": token})
    gate.decide(replay)

    assert len(asked) == 1, "the replayed call must be asked about again"
    assert asked[0].arguments["path"] == "b.txt"


def test_the_matching_token_lets_the_call_through_without_asking() -> None:
    asked: list = []
    gate = make_gate(asked=asked)
    message = call("write_file", {"path": "a.txt", "content": "hi"})
    token = gate.approver.grant(
        gate.approver.pending("fixture", "write_file", message["params"]["arguments"])
    )
    message["params"]["_meta"] = {"veto_token": token}

    decision = gate.decide(message)
    assert decision.forward is True
    assert asked == []


def test_a_forged_token_is_refused() -> None:
    asked: list = []
    gate = make_gate(asked=asked)
    message = call(
        "write_file", {"path": "a.txt", "content": "hi"}, _meta={"veto_token": "v1.9999999999.AAAA"}
    )
    gate.decide(message)
    assert len(asked) == 1


# --------------------------------------------------------------------------
# End to end: two real processes, a real file on disk.
# --------------------------------------------------------------------------


class Proxy:
    """Drives the real CLI as a client would, over real pipes."""

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace
        self.proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "mcp_veto",
                "run",
                "--timeout",
                "30",
                "--",
                sys.executable,
                str(FIXTURE),
                str(workspace),
            ],
            cwd=str(ROOT),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.lines: queue.Queue[str | None] = queue.Queue()
        self.errs: queue.Queue[str | None] = queue.Queue()
        threading.Thread(target=self._pump, args=(self.proc.stdout, self.lines), daemon=True).start()
        threading.Thread(target=self._pump, args=(self.proc.stderr, self.errs), daemon=True).start()

    @staticmethod
    def _pump(stream, sink: queue.Queue) -> None:
        for line in stream:
            sink.put(line)
        sink.put(None)

    def send(self, message: dict) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(message) + "\n")
        self.proc.stdin.flush()

    def receive(self, timeout: float = 5.0) -> dict | None:
        try:
            line = self.lines.get(timeout=timeout)
        except queue.Empty:
            return None
        if line is None:
            return None
        return json.loads(line)

    def wait_for_url(self, timeout: float = 10.0) -> str:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                line = self.errs.get(timeout=deadline - time.monotonic())
            except queue.Empty:
                break
            if line and "/a/" in line:
                for word in line.split():
                    if word.startswith("http://127.0.0.1") and "/a/" in word:
                        return word.strip()
        raise AssertionError("the gate never announced an approval URL")

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def approve(url: str, decision: str) -> None:
    body = urllib.parse.urlencode({"decision": decision}).encode()
    urllib.request.urlopen(urllib.request.Request(url, data=body), timeout=5).read()


def test_a_real_write_is_held_then_executed_on_approval(tmp_path: Path) -> None:
    proxy = Proxy(tmp_path)
    try:
        proxy.send(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "t", "version": "0"},
                },
            }
        )
        assert proxy.receive()["result"]["serverInfo"]["name"] == "fixture"

        proxy.send(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "write_file",
                    "arguments": {"path": "secret.txt", "content": "classified"},
                },
            }
        )

        url = proxy.wait_for_url()
        assert proxy.receive(timeout=2.0) is None, "the call must not be answered before approval"
        assert not (tmp_path / "secret.txt").exists(), "the write must not have reached the server"

        approve(url, "approve")

        reply = proxy.receive(timeout=10.0)
        assert reply["id"] == 2
        assert "result" in reply
        assert (tmp_path / "secret.txt").read_text() == "classified"
    finally:
        proxy.close()


def test_a_refused_write_leaves_the_disk_untouched(tmp_path: Path) -> None:
    proxy = Proxy(tmp_path)
    try:
        proxy.send(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "t", "version": "0"},
                },
            }
        )
        proxy.receive()

        proxy.send(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "write_file", "arguments": {"path": "nope.txt", "content": "x"}},
            }
        )
        url = proxy.wait_for_url()
        approve(url, "deny")

        reply = proxy.receive(timeout=10.0)
        assert reply["id"] == 3
        assert reply["error"]["code"] == -32001
        assert not (tmp_path / "nope.txt").exists()
    finally:
        proxy.close()
