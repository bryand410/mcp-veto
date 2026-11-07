"""Put the Auth0 tenant in the state `demo/tokenvault.py` expects, through the
Management API instead of the dashboard.

    export AUTH0_DOMAIN=dev-xxxx.us.auth0.com
    export AUTH0_CLIENT_ID=...
    export AUTH0_CLIENT_SECRET=...   # this application must be authorised on
                                     # the Auth0 Management API (client grant)

    python demo/auth0_setup.py

Idempotent. Every step reads the current state first, prints what it found, and
changes only what is wrong. A failure names the step and the component that
refused, never the one that suffered.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

DOMAIN = os.environ.get("AUTH0_DOMAIN", "")
CLIENT_ID = os.environ.get("AUTH0_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("AUTH0_CLIENT_SECRET", "")

CALLBACK = "http://127.0.0.1:8765/callback"
LOGOUT = "http://127.0.0.1:8765"
CONNECTION = os.environ.get("AUTH0_CONNECTION", "github")
SCOPES = ["repo", "read:user"]

API = f"https://{DOMAIN}/api/v2"


def step(n: int, title: str) -> None:
    print(f"\n{n}. {title}")


def call(method: str, path: str, token: str, body: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{API}{path}", data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/json")
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            raw = response.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")
        raise SystemExit(
            f"   Management API refused {method} {path}\n"
            f"   HTTP {error.code}: {detail[:600]}"
        ) from None


def management_token() -> str:
    payload = json.dumps(
        {
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "audience": f"https://{DOMAIN}/api/v2/",
        }
    ).encode()
    req = urllib.request.Request(
        f"https://{DOMAIN}/oauth/token",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.loads(response.read())["access_token"]
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")
        raise SystemExit(
            "   the tenant refused a Management API token\n"
            f"   HTTP {error.code}: {detail[:600]}\n\n"
            "   Fix: Dashboard -> Applications -> APIs -> Auth0 Management API\n"
            "        -> Machine to Machine Applications -> authorise this app."
        ) from None


def main() -> int:
    missing = [
        name
        for name, value in (
            ("AUTH0_DOMAIN", DOMAIN),
            ("AUTH0_CLIENT_ID", CLIENT_ID),
            ("AUTH0_CLIENT_SECRET", CLIENT_SECRET),
        )
        if not value
    ]
    if missing:
        raise SystemExit(f"missing: {', '.join(missing)}")

    step(1, "management token")
    token = management_token()
    print(f"   ok, {len(token)} chars")

    step(2, "application callback URLs")
    client = call("GET", f"/clients/{CLIENT_ID}", token)
    callbacks = client.get("callbacks") or []
    logouts = client.get("allowed_logout_urls") or []
    print(f"   callbacks now: {callbacks or '(none)'}")
    patch: dict = {}
    if CALLBACK not in callbacks:
        patch["callbacks"] = callbacks + [CALLBACK]
    if LOGOUT not in logouts:
        patch["allowed_logout_urls"] = logouts + [LOGOUT]
    if patch:
        call("PATCH", f"/clients/{CLIENT_ID}", token, patch)
        print(f"   patched: {', '.join(patch)}")
    else:
        print("   already correct")

    step(3, f"connection '{CONNECTION}'")
    connections = call("GET", "/connections?strategy=github", token)
    found = next((c for c in connections if c.get("name") == CONNECTION), None)
    if found is None:
        print("   absent, creating it with Auth0 developer keys")
        found = call(
            "POST",
            "/connections",
            token,
            {
                "name": CONNECTION,
                "strategy": "github",
                "display_name": "GitHub",
                "options": {
                    "scopes": SCOPES,
                    "set_user_root_attributes": "on_each_login",
                },
            },
        )
        print(f"   created id={found.get('id')}")
    else:
        print(f"   present id={found.get('id')}")

    step(4, "attach the application to the connection")
    # `enabled_clients` is read-only on PATCH /connections since the API Access
    # rework: the tenant answers "Additional properties not allowed". The
    # attachment is read back from its own endpoint instead of guessed at.
    attached = [
        c.get("client_id")
        for c in call("GET", f"/connections/{found['id']}/clients", token).get("clients", [])
    ]
    print(f"   clients on the connection: {attached or '(none)'}")
    if CLIENT_ID in attached:
        print("   already attached")
    else:
        raise SystemExit(
            "   this application is not attached to the connection, and the API\n"
            "   refuses to attach it (enabled_clients is read-only).\n"
            "   Dashboard -> Applications -> this app -> Connections tab -> GitHub."
        )

    step(5, "token vault on this connection")
    vault = (found.get("connected_accounts") or {}).get("active")
    print(f"   connected_accounts.active = {vault}")
    if not vault:
        call("PATCH", f"/connections/{found['id']}", token, {"connected_accounts": {"active": True}})
        print("   switched on")

    step(6, "state after setup")
    client = call("GET", f"/clients/{CLIENT_ID}", token)
    found = next(
        c
        for c in call("GET", "/connections?strategy=github", token)
        if c.get("name") == CONNECTION
    )
    print(f"   callbacks: {client.get('callbacks')}")
    print(f"   connection attached: {CLIENT_ID in attached}")
    print(f"   connection scopes: {(found.get('options') or {}).get('scopes')}")
    print(f"   token vault: {(found.get('connected_accounts') or {}).get('active')}")

    print("\n   next:")
    print(f"     export AUTH0_DOMAIN={DOMAIN}")
    print(f"     export AUTH0_CLIENT_ID={CLIENT_ID}")
    print("     export AUTH0_CLIENT_SECRET=<secret>")
    print("     python demo/tokenvault.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
