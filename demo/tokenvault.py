"""Prove Token Vault end to end: connect a GitHub account through the My Account
API, take a GitHub token out of the vault, then gate the write that uses it.

    export AUTH0_DOMAIN=dev-xxxx.us.auth0.com
    export AUTH0_CLIENT_ID=...
    export AUTH0_CLIENT_SECRET=...
    python demo/tokenvault.py

Steps, each one printed before it runs so a failure names the step that broke:

  1. discovery    the tenant answers OIDC discovery
  2. login        browser -> Auth0 -> a refresh token and a My Account API token
  3. connect      ask the My Account API to link a GitHub account
  4. consent      browser -> GitHub -> connect_code on 127.0.0.1
  5. complete     the My Account API stores the GitHub tokens in the vault
  6. exchange     refresh token -> GitHub token, out of the vault
  7. proof        that token really is GitHub's: GET /user
  8. gated write  mcp-veto holds the write until a human approves it

Why the connect flow and not a plain social login: a normal login through a
social connection leaves nothing in the vault. Auth0 answers
`federated_connection_refresh_token_not_found` until a connected account
exists, and connected accounts are created by the My Account API, not by
`/authorize`.
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mcp_veto.approval import Approver
from mcp_veto.policy import Policy
from mcp_veto.ui import ApprovalServer

DOMAIN = os.environ.get("AUTH0_DOMAIN", "")
CLIENT_ID = os.environ.get("AUTH0_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("AUTH0_CLIENT_SECRET", "")
CONNECTION = os.environ.get("AUTH0_CONNECTION", "github")
CONNECTION_SCOPE = os.environ.get("GITHUB_SCOPES", "repo read:user")
PORT = 8765
REDIRECT_URI = f"http://127.0.0.1:{PORT}/callback"
ME_AUDIENCE = f"https://{DOMAIN}/me/"
ME_SCOPES = (
    "openid profile email offline_access "
    "create:me:connected_accounts read:me:connected_accounts"
)

TOKEN_VAULT_GRANT = "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token"
TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
REFRESH_TYPE = "urn:ietf:params:oauth:token-type:refresh_token"
REQUESTED = "http://auth0.com/oauth/token-type/federated-connection-access-token"

PAGE = b"""<!doctype html><meta charset="utf-8"><title>mcp-veto</title>
<body style="background:#0b0d10;color:#c9d1d9;font:15px ui-monospace,monospace;
display:grid;place-items:center;height:100vh;margin:0">
<div style="text-align:center;line-height:1.7">
<div id="m">Retour du fournisseur...</div>
<div style="color:#6e7681;font-size:12px">mcp-veto / token vault</div></div>
<script>
// The connect_code comes back in the fragment, and a fragment never reaches a
// server. So the page reads it and hands it over itself.
const h = new URLSearchParams(location.hash.slice(1));
const q = new URLSearchParams(location.search);
const p = h.has("connect_code") ? h : q;
const msg = document.getElementById("m");
if (p.has("connect_code") || p.has("error")) {
  fetch("/_capture?" + p.toString())
    .then(() => { msg.textContent = "Autorisation recue. Fermez cet onglet."; })
    .catch(() => { msg.textContent = "Le code n'a pas pu etre transmis."; });
} else {
  msg.textContent = "Rien a transmettre.";
}
</script></body>"""


def step(n: int, title: str) -> None:
    print(f"\n{n}. {title}")


def get_json(url: str, token: str | None = None) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.loads(response.read())


def post_json(url: str, payload: dict, token: str | None = None) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            raw = response.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode()
        raise SystemExit(f"    HTTP {exc.code} from {url}\n    {body}") from None


def try_post(url: str, payload: dict) -> dict:
    """Like post_json, but returns the error body instead of exiting, so the
    caller can print the refusal verbatim instead of dying on it."""
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        try:
            return {"_error": json.loads(raw)}
        except ValueError:
            return {"_error": {"error": f"HTTP {exc.code}", "error_description": raw[:300]}}


class _Callback(BaseHTTPRequestHandler):
    captured: dict = {}
    done = threading.Event()

    def log_message(self, *args) -> None:
        pass

    def _send(self, code: int, body: bytes, kind: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        query = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}

        if parsed.path == "/_capture":
            type(self).captured = query
            type(self).done.set()
            self._send(204, b"", "text/plain")
            return
        if parsed.path != "/callback":
            self._send(404, b"not found", "text/plain")
            return

        # A login code arrives in the query and is captured here. A connect_code
        # arrives in the fragment, which never reaches the server, so the page
        # posts it back to /_capture instead.
        if "code" in query or "error" in query:
            type(self).captured = query
            type(self).done.set()
        self._send(200, PAGE, "text/html; charset=utf-8")


def _listen() -> HTTPServer:
    server = HTTPServer(("127.0.0.1", PORT), _Callback)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _wait_for(what: str, timeout: int = 300) -> dict:
    if not _Callback.done.wait(timeout=timeout):
        print(f"   nobody completed {what} within {timeout // 60} minutes")
        raise SystemExit(1)
    got = dict(_Callback.captured)
    _Callback.captured = {}
    _Callback.done.clear()
    if "error" in got:
        print(f"   Auth0 refused: {got['error']}")
        print(f"   {got.get('error_description')}")
        raise SystemExit(1)
    return got


def main() -> int:
    missing = [
        k
        for k in ("AUTH0_DOMAIN", "AUTH0_CLIENT_ID", "AUTH0_CLIENT_SECRET")
        if not os.environ.get(k)
    ]
    if missing:
        print(f"missing: {', '.join(missing)} - see SETUP-TOKENVAULT.md")
        return 2
    base = f"https://{DOMAIN}"

    step(1, "discovery")
    discovery = get_json(f"{base}/.well-known/openid-configuration")
    print("   issuer     :", discovery["issuer"])
    print("   authorize  :", discovery["authorization_endpoint"])
    print("   token      :", discovery["token_endpoint"])
    server = _listen()
    print("   callback   :", REDIRECT_URI)

    step(2, "login, asking for a token the My Account API will accept")
    state = secrets.token_urlsafe(16)
    url = f"{discovery['authorization_endpoint']}?" + urllib.parse.urlencode(
        {
            "client_id": CLIENT_ID,
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
            "scope": ME_SCOPES,
            "state": state,
            "connection": CONNECTION,
            "audience": ME_AUDIENCE,
            "prompt": "consent",
        }
    )
    webbrowser.open(url)
    got = _wait_for("the login")
    if got.get("state") != state:
        print("   state mismatch - refusing the code")
        return 1
    print("   code received")

    tokens = post_json(
        discovery["token_endpoint"],
        {
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code": got["code"],
            "redirect_uri": REDIRECT_URI,
        },
    )
    me_token = tokens.get("access_token", "")
    refresh_token = tokens.get("refresh_token", "")
    print("   My Account token:", f"{len(me_token)} chars" if me_token else "MISSING")
    print("   refresh token  :", f"{len(refresh_token)} chars" if refresh_token else "MISSING")
    if not me_token or not refresh_token:
        print("   ", json.dumps(tokens)[:400])
        return 1

    step(3, f"ask the My Account API to link {CONNECTION}")
    request = post_json(
        f"{base}/me/v1/connected-accounts/connect",
        {
            "connection": CONNECTION,
            "redirect_uri": REDIRECT_URI,
            "state": secrets.token_urlsafe(16),
            "scopes": CONNECTION_SCOPE.split(),
        },
        token=me_token,
    )
    auth_session = request.get("auth_session", "")
    connect_uri = request.get("connect_uri", "")
    params = request.get("connect_params") or {}
    print("   auth_session:", (auth_session[:12] + "...") if auth_session else "MISSING")
    print("   connect_uri :", connect_uri)
    if not auth_session or not connect_uri:
        print("   ", json.dumps(request)[:400])
        return 1

    step(4, f"consent: the browser is opening on {CONNECTION}")
    joiner = "&" if "?" in connect_uri else "?"
    webbrowser.open(f"{connect_uri}{joiner}{urllib.parse.urlencode(params)}")
    got = _wait_for("the consent screen")
    connect_code = got.get("connect_code", "")
    if not connect_code:
        print("   no connect_code on the callback:", json.dumps(got)[:300])
        return 1
    print("   connect_code received")

    step(5, "the My Account API stores the tokens")
    stored = post_json(
        f"{base}/me/v1/connected-accounts/complete",
        {
            "auth_session": auth_session,
            "connect_code": connect_code,
            "redirect_uri": REDIRECT_URI,
        },
        token=me_token,
    )
    print("   connected account:", stored.get("id"))
    print("   scopes           :", stored.get("scopes"))
    print("   access_type      :", stored.get("access_type"))
    if not stored.get("id"):
        print("   ", json.dumps(stored)[:400])
        return 1

    step(6, "refresh token -> GitHub token, out of the vault")
    vault = try_post(
        discovery["token_endpoint"],
        {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "subject_token": refresh_token,
            "grant_type": TOKEN_VAULT_GRANT,
            "subject_token_type": REFRESH_TYPE,
            "requested_token_type": REQUESTED,
            "connection": CONNECTION,
        },
    )
    github_token = vault.get("access_token", "")
    if github_token:
        print("   exchange    : refresh token")
    else:
        refusal = vault.get("_error") or {}
        print("   refused     :", refusal.get("error"))
        print("   ", refusal.get("error_description"))
    print("   GitHub token:", f"{len(github_token)} chars" if github_token else "MISSING")
    print("   scope       :", vault.get("scope"))
    print("   expires_in  :", vault.get("expires_in"))
    if not github_token:
        print("   ", json.dumps(vault)[:400])
        return 1

    step(7, "the vaulted token really is GitHub's")
    me = get_json("https://api.github.com/user", github_token)
    print("   authenticated as:", me.get("login"), f"({me.get('public_repos')} public repos)")

    step(8, "a write with that token, held by mcp-veto")
    repo = os.environ.get("DEMO_REPO", f"{me.get('login')}/mcp-veto-demo")
    action = {
        "method": "POST",
        "url": f"https://api.github.com/repos/{repo}/issues",
        "body": {
            "title": "Opened by an agent, with a token from Token Vault",
            "body": "Approved out of band.",
        },
    }
    tool = "create_issue"
    policy = Policy.default()
    if not policy.requires_approval(tool):
        print("   policy does not require approval for this tool - demo misconfigured")
        return 1

    approvals = ApprovalServer(ttl=180)
    approver = Approver(ttl=180)
    pending = approver.pending("github", tool, action)
    approvals.register(pending)
    print(f"   needs approval: {tool} on {repo}")
    print(f"   -> {approvals.url_for(pending)}")
    verdict = approvals.wait(pending)

    if verdict is not True:
        print("   refused (or timed out). Nothing was sent to GitHub.")
        return 0
    print("   approved. sending with the vaulted token.")
    req = urllib.request.Request(
        action["url"],
        data=json.dumps(action["body"]).encode(),
        headers={
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            created = json.loads(response.read())
        print("   created:", created.get("html_url"))
    except urllib.error.HTTPError as exc:
        print(f"   GitHub said {exc.code}: {exc.read().decode()[:200]}")
        return 1
    approvals.close()
    server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
