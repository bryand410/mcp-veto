"""The gate itself: a stdio proxy that stops one call and waits for a human."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TextIO

from .approval import Approver, PendingApproval
from .policy import Policy

REFUSED = -32001
TIMED_OUT = -32002
DENIED = -32003


def _error(message: dict[str, Any], code: int, text: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message.get("id"), "error": {"code": code, "message": text}}


@dataclass
class Decision:
    """What to do with one client message."""

    forward: bool
    request: dict[str, Any]
    reply: dict[str, Any] | None = None
    pending: PendingApproval | None = None


class Gate:
    def __init__(
        self,
        policy: Policy,
        approver: Approver,
        ask: Callable[[PendingApproval], bool | None],
        server_name: str = "server",
    ) -> None:
        self.policy = policy
        self.approver = approver
        self.ask = ask
        self.server_name = server_name

    # -- decision -----------------------------------------------------------

    def decide(self, message: dict[str, Any]) -> Decision:
        if message.get("method") != "tools/call":
            return Decision(forward=True, request=message)

        params = message.get("params") or {}
        tool = str(params.get("name") or "")
        arguments = params.get("arguments") or {}

        if self.policy.is_denied(tool):
            return Decision(
                forward=False,
                request=message,
                reply=_error(message, DENIED, f"{tool}: refused by policy, no approval can unlock it"),
            )

        token = (params.get("_meta") or {}).get("veto_token")
        if token and self.approver.check(token, self.server_name, tool, arguments):
            return Decision(forward=True, request=message)

        if not self.policy.requires_approval(tool):
            return Decision(forward=True, request=message)

        pending = self.approver.pending(self.server_name, tool, arguments)
        verdict = self.ask(pending)

        if verdict is True:
            return Decision(forward=True, request=message, pending=pending)
        if verdict is False:
            return Decision(
                forward=False,
                request=message,
                reply=_error(message, REFUSED, f"{tool}: refused by the operator"),
                pending=pending,
            )
        return Decision(
            forward=False,
            request=message,
            reply=_error(
                message,
                TIMED_OUT,
                f"{tool}: timed out waiting for approval after {int(pending.expires_at - pending.requested_at)}s",
            ),
            pending=pending,
        )

    # -- plumbing -----------------------------------------------------------

    def run(self, command: list[str], stdin: TextIO | None = None, stdout: TextIO | None = None) -> int:
        stdin = stdin or sys.stdin
        stdout = stdout or sys.stdout
        proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,  # the server's own logs stay visible to the operator
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        lock = threading.Lock()

        def emit(payload: str) -> None:
            with lock:
                stdout.write(payload + "\n")
                stdout.flush()

        def pump() -> None:
            assert proc.stdout is not None
            for line in proc.stdout:
                line = line.strip()
                if line:
                    emit(line)

        threading.Thread(target=pump, daemon=True).start()

        try:
            for line in stdin:
                line = line.strip()
                if not line:
                    continue
                try:
                    message = json.loads(line)
                except json.JSONDecodeError:
                    _write(proc, line)
                    continue

                decision = self.decide(message)
                if decision.forward:
                    _write(proc, json.dumps(decision.request))
                elif decision.reply is not None:
                    emit(json.dumps(decision.reply))
        except (BrokenPipeError, KeyboardInterrupt):
            pass
        finally:
            if proc.stdin is not None:
                try:
                    proc.stdin.close()
                except OSError:
                    pass
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        return 0


def _write(proc: subprocess.Popen[str], payload: str) -> None:
    if proc.stdin is None:
        return
    proc.stdin.write(payload + "\n")
    proc.stdin.flush()
