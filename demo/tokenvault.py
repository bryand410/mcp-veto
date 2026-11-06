"""Prove Token Vault end to end: get a GitHub token out of the vault, then
gate the write that uses it.

    export AUTH0_DOMAIN=dev-xxxx.us.auth0.com
    export AUTH0_CLIENT_ID=...
    export AUTH0_CLIENT_SECRET=...
    python demo/tokenvault.py

Steps, each one printed before it runs so a failure names the step that broke:
  1. discovery        the tenant answers OIDC discovery
  2. login            browser -> Auth0 -> GitHub consent -> code on 127.0.0.1
  3. auth0 token      code -> Auth0 access token
  4. vault            Auth0 token -> GitHub token, out of Token Vault
  5. proof            that token really is GitHub's: GET /user
  6. gated write      mcp-veto holds the write until a human approves it
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
AUDIENCE = os.environ.get("AUTH0_AUDIENCE", "")

TOKEN_VAULT_GRANT = "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token"
TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
REQUESTED = "http://auth0.com/oauth/token-type/federated-connection-access-token"


def step(n: int, title: str) -> None:
    print(f"\n{n}. {title}")


def get_json(url: str, token: str | None = None) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.loads(response.read())


def post_json(url: str, payload: dict) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode()
        raise SystemExit(f"    HTTP {exc.code} from {url}\n    {body}") from None


class _Callback(BaseHTTPRequestHandler):
    code: str | None = None
    state: str | None = None
    done = threading.Event()

    def log_message(self, *args) -> None:
        pass

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/callback":
            self.send_response(404)
            self.end_headers()
            return
        query = urllib.parse.parse_qs(parsed.query)
        type(self).code = (query.get("code") or [None])[0]
        type(self).state = (query.get("state") or [None])[0]
        body = b"<meta charset='utf-8'><body style='background:#0b0d10;color:#3fb950;font:16px monospace;display:grid;place-items:center;height:100vh'>Autorisation recue. Vous pouvez fermer cet onglet.</body>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        type(self).done.set()


def main() -> int:
    missing = [k for k in ("AUTH0_DOMAIN", "AUTH0_CLIENT_ID", "AUTH0_CLIENT_SECRET") if not os.environ.get(k)]
    if missing:
        print(f"missing: {', '.join(missing)} - see SETUP-TOKENVAULT.md")
        return 2
    base = f"https://{DOMAIN}"

    step(1, "discovery")
    discovery = get_json(f"{base}/.well-known/openid-configuration")
    print("   issuer     :", discovery["issuer"])
    print("   authorize  :", discovery["authorization_endpoint"])
    print("   token      :", discovery["token_endpoint"])

    step(2, "login through", CONNECTION)
    state = secrets.token_urlsafe(16)
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": "openid profile email offline_access",
        "state": state,
        "connection": CONNECTION,
        "connection_scope": CONNECTION_SCOPE,
        "access_type": "offline",
        "prompt": "consent",
    }
    if AUDIENCE:
        params["audience"] = AUDIENCE
    url = f"{discovery['authorization_endpoint']}?{urllib.parse.urlencode(params)}"
    print("   open this if the browser does not:", url[:110] + "...")

    server = HTTPServer(("127.0.0.1", PORT), _Callback)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    webbrowser.open(url)
    if not _Callback.done.wait(timeout=300):
        print("   nobody completed the login within 5 minutes")
        return 1
    server.shutdown()
    if not _Callback.code:
        print("   no code came back on the callback")
        return 1
    if _Callback.state != state:
        print("   state mismatch - refusing the code")
        return 1
    print("   code received")

    step(3, "code -> Auth0 access token")
    auth0 = post_json(
        discovery["token_endpoint"],
        {
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code": _Callback.code,
            "redirect_uri": REDIRECT_URI,
        },
    )
    subject_token = auth0.get("access_token", "")
    print("   Auth0 token:", f"{len(subject_token)} chars, expires in {auth0.get('expires_in')}s")
    if not subject_token:
        print("   ", json.dumps(auth0)[:300])
        return 1

    step(4, "Auth0 token -> GitHub token, out of Token Vault")
    vault = post_json(
        discovery["token_endpoint"],
        {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "subject_token": subject_token,
            "grant_type": TOKEN_VAULT_GRANT,
            "subject_token_type": TOKEN_TYPE,
            "requested_token_type": REQUESTED,
            "connection": CONNECTION,
        },
    )
    github_token = vault.get("access_token", "")
    print("   GitHub token:", f"{len(github_token)} chars" if github_token else "MISSING")
    print("   scope       :", vault.get("scope"))
    print("   expires_in  :", vault.get("expires_in"))
    if not github_token:
        print("   ", json.dumps(vault)[:400])
        return 1

    step(5, "the vault token really is GitHub's")
    me = get_json("https://api.github.com/user", github_token)
    print("   authenticated as:", me.get("login"), f"({me.get('public_repos')} public repos)")

    step(6, "a write with that token, held by mcp-veto")
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
