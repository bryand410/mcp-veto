"""The out-of-band channel: a page on loopback that the agent cannot click.

Loopback only, one random path per request, no state in the URL that a caller
could forge. The gate is the only writer of decisions; the browser is only a
transport for a human's click.
"""

from __future__ import annotations

import html
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .approval import PendingApproval


class _State:
    def __init__(self) -> None:
        self.pending: dict[str, PendingApproval] = {}
        self.events: dict[str, threading.Event] = {}
        self.decisions: dict[str, bool] = {}


_PAGE = """<!doctype html>
<meta charset="utf-8">
<title>Approve {tool}</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; min-height: 100vh; display: grid; place-items: center;
         background: #0b0d10; color: #e6e8eb;
         font: 15px/1.55 ui-monospace, SFMono-Regular, Menlo, monospace; }}
  main {{ width: min(760px, 92vw); padding: 28px 30px 30px;
          border: 1px solid #22272e; border-radius: 14px; background: #11151a; }}
  .tag {{ display: inline-block; padding: 3px 9px; border-radius: 999px;
          background: #2a1a12; color: #ff9d5c; font-size: 12px; letter-spacing: .04em; }}
  h1 {{ font-size: 19px; margin: 14px 0 4px; }}
  h1 code {{ color: #ffd479; }}
  p.lead {{ margin: 0 0 18px; color: #8b949e; font-size: 13px; }}
  pre {{ margin: 0 0 16px; padding: 14px 16px; border-radius: 10px;
         background: #0a0d11; border: 1px solid #1c222a; overflow-x: auto;
         white-space: pre-wrap; word-break: break-word; color: #c9d1d9; font-size: 13px; }}
  dl {{ display: grid; grid-template-columns: 96px 1fr; gap: 6px 14px; margin: 0 0 22px; font-size: 13px; }}
  dt {{ color: #6e7681; }}
  dd {{ margin: 0; color: #c9d1d9; }}
  .row {{ display: flex; gap: 12px; }}
  button {{ flex: 1; padding: 12px 16px; border-radius: 9px; border: 1px solid transparent;
            font: inherit; font-weight: 600; cursor: pointer; }}
  .yes {{ background: #1f6f43; color: #eafff2; }}
  .yes:hover {{ background: #23814e; }}
  .no {{ background: #1a1e24; color: #d7dce2; border-color: #2b323b; }}
  .no:hover {{ background: #222831; }}
  footer {{ margin-top: 18px; color: #4d5560; font-size: 12px; }}
</style>
<main>
  <span class="tag">MCP · approbation requise</span>
  <h1>L'agent veut exécuter <code>{tool}</code></h1>
  <p class="lead">Rien n'a été exécuté. Le serveur attend votre réponse.</p>
  <pre>{arguments}</pre>
  <dl>
    <dt>serveur</dt><dd>{server}</dd>
    <dt>empreinte</dt><dd>{digest}</dd>
    <dt>expire</dt><dd>dans {seconds} s</dd>
  </dl>
  <form method="post" action="/a/{id}">
    <div class="row">
      <button class="yes" name="decision" value="approve">Approuver</button>
      <button class="no" name="decision" value="deny">Refuser</button>
    </div>
  </form>
  <footer>Un « approuver » ne vaut que pour cet appel exact, arguments compris.</footer>
</main>
"""

_DONE = """<!doctype html>
<meta charset="utf-8"><title>{title}</title>
<style> body {{ margin:0; min-height:100vh; display:grid; place-items:center;
  background:#0b0d10; color:{colour}; font:16px/1.6 ui-monospace, monospace; }} </style>
<p>{title}</p>
"""


def _handler(state: _State, ttl: float) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args: Any) -> None:
            pass

        def _send(self, code: int, body: str, ctype: str = "text/html; charset=utf-8") -> None:
            payload = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            key = self.path.rstrip("/").rsplit("/", 1)[-1]
            pending = state.pending.get(key)
            if pending is None:
                self._send(404, _DONE.format(title="Demande inconnue", colour="#ff7b72"))
                return
            self._send(
                200,
                _PAGE.format(
                    tool=html.escape(pending.tool),
                    arguments=html.escape(pending.summary()),
                    server=html.escape(pending.server),
                    digest=pending.digest[:32],
                    seconds=pending.seconds_left,
                    id=html.escape(pending.id),
                ),
            )

        def do_POST(self) -> None:
            key = self.path.rstrip("/").rsplit("/", 1)[-1]
            if key not in state.pending:
                self._send(404, _DONE.format(title="Demande inconnue", colour="#ff7b72"))
                return
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode()
            approved = "decision=approve" in body
            state.decisions[key] = approved
            state.events[key].set()
            if approved:
                self._send(200, _DONE.format(title="Approuvé — l'appel repart", colour="#3fb950"))
            else:
                self._send(200, _DONE.format(title="Refusé — l'appel est bloqué", colour="#ff7b72"))

    return Handler


class ApprovalServer:
    """Serves the approval page on 127.0.0.1 and blocks until a human answers."""

    def __init__(self, ttl: float = 120.0) -> None:
        self._state = _State()
        self._ttl = ttl
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _handler(self._state, ttl))
        self._httpd.daemon_threads = True
        self.port = self._httpd.server_address[1]
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def url_for(self, pending: PendingApproval) -> str:
        return f"{self.base}/a/{pending.id}"

    def ask(self, pending: PendingApproval) -> bool | None:
        self.register(pending)
        return self.wait(pending)

    def register(self, pending: PendingApproval) -> None:
        """Make the page answerable before the URL is announced anywhere."""
        self._state.pending[pending.id] = pending
        self._state.events[pending.id] = threading.Event()

    def wait(self, pending: PendingApproval) -> bool | None:
        event = self._state.events[pending.id]
        deadline = time.monotonic() + max(1.0, pending.expires_at - time.time())
        if not event.wait(timeout=deadline):
            return None
        return self._state.decisions.get(pending.id)

    def forget(self, pending: PendingApproval) -> None:
        self._state.pending.pop(pending.id, None)
        self._state.events.pop(pending.id, None)
        self._state.decisions.pop(pending.id, None)

    def close(self) -> None:
        self._httpd.shutdown()
