"""Approval objects and the signed token that proves one happened.

The token exists for one reason: an approval must not be a blanket yes. It is
signed over the server name, the tool name and a digest of the exact arguments,
so a yes for "write report.txt" cannot be replayed for "write ~/.ssh/authorized_keys".
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any


def canonical(arguments: dict[str, Any]) -> str:
    """The same bytes for the same call, whatever the key order."""
    return json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_of(server: str, tool: str, arguments: dict[str, Any]) -> str:
    material = f"{server}\x1f{tool}\x1f{canonical(arguments)}".encode()
    return hashlib.sha256(material).hexdigest()


@dataclass(frozen=True)
class PendingApproval:
    """One call, waiting for one human."""

    id: str
    server: str
    tool: str
    arguments: dict[str, Any]
    digest: str
    expires_at: float
    url: str = ""
    requested_at: float = field(default_factory=time.time)

    @property
    def seconds_left(self) -> int:
        return max(0, int(self.expires_at - time.time()))

    def summary(self) -> str:
        return f"{self.tool}({canonical(self.arguments)[:300]})"


class Approver:
    """Issues pending approvals and verifies the tokens that close them."""

    def __init__(
        self,
        secret: bytes | None = None,
        ttl: float = 120.0,
        clock=time.time,
    ) -> None:
        self._secret = secret or os.environ.get("MCP_VETO_SECRET", "").encode() or secrets.token_bytes(32)
        self._ttl = ttl
        self._clock = clock

    def pending(self, server: str, tool: str, arguments: dict[str, Any], url: str = "") -> PendingApproval:
        return PendingApproval(
            id=secrets.token_urlsafe(9),
            server=server,
            tool=tool,
            arguments=arguments,
            digest=digest_of(server, tool, arguments),
            expires_at=self._clock() + self._ttl,
            url=url,
        )

    def grant(self, pending: PendingApproval) -> str:
        expires = int(pending.expires_at)
        return f"v1.{expires}.{self._sign(pending.digest, expires)}"

    def check(self, token: str, server: str, tool: str, arguments: dict[str, Any]) -> bool:
        try:
            version, raw_expires, signature = token.split(".")
            if version != "v1":
                return False
            expires = int(raw_expires)
        except (ValueError, AttributeError):
            return False
        if expires < self._clock():
            return False
        expected = self._sign(digest_of(server, tool, arguments), expires)
        return hmac.compare_digest(expected, signature)

    def _sign(self, digest: str, expires: int) -> str:
        message = f"{digest}\x1f{expires}".encode()
        mac = hmac.new(self._secret, message, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(mac).decode().rstrip("=")
