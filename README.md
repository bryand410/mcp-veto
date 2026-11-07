# mcp-veto

A stdio proxy for MCP servers that stops one tool call and waits for a human.

The scanner tells you which servers *can* do damage. This one decides, at the
moment of the call, whether they are *allowed* to.

```
client  ──stdio──▶  mcp-veto  ──stdio──▶  real MCP server
                        │
                        └── 127.0.0.1/approval page ──▶ human
```

## Why

An agent that can write files, send mail or run commands will eventually be
asked to do something irreversible, and the model asking has no way to be
wrong safely. The pattern that fixes this is the one banks use for phone
banking: **the sensitive action is suspended, and approval arrives on a channel
the requester does not control.**

That pattern is CIBA (Client-Initiated Backchannel Authentication). Vendors sell
it as a feature; it is really three rules:

1. the call is held before it executes, not logged after,
2. the approval is bound to *that exact call*, arguments included,
3. the approval expires.

This is those three rules, in 500 lines of standard library, with no account
and no phone.

## Use

```bash
python -m mcp_veto run -- npx -y @modelcontextprotocol/server-filesystem /srv/data
```

Point your MCP client at `mcp-veto run ...` instead of the server. On a
sensitive call the gate prints:

```
[veto] approval needed: http://127.0.0.1:54017/a/DC-76BqG9cTo
```

Open it, read the exact arguments, approve or refuse. The call then executes,
or is answered with a JSON-RPC error and never reaches the server.

```bash
mcp-veto run --policy veto.json --timeout 300 -- <command>
```

| flag | meaning |
|---|---|
| `--policy FILE` | `{"require_approval_patterns": [...], "allow": [...], "deny": [...]}` |
| `--timeout N` | seconds to wait for a human (default 120) |
| `--server NAME` | name bound into the approval token (default `server`) |

Default policy: any tool whose name matches `write|edit|create|delete|remove|
move|rename|chmod|exec|run|shell|spawn|install|push|merge|publish|send|post|
pay|refund`. Names, not descriptions — a gate sits on the hot path and cannot
afford to guess intent from prose.

## Error codes

| code | meaning |
|---|---|
| `-32001` | refused by the operator |
| `-32002` | nobody answered before the deadline |
| `-32003` | refused by policy; no approval can unlock it |

## Pre-approval

The approval token is `v1.<expiry>.<hmac>` over `sha256(server ␟ tool ␟ canonical(arguments))`.
Pass it as `params._meta.veto_token` to let an automated caller through without
a page:

```python
from mcp_veto import Approver
approver = Approver(secret=b"...")          # same secret on both sides
pending = approver.pending("filesystem", "write_file", {"path": "/srv/data/report.csv", "content": "..."})
token = approver.grant(pending)             # expires with the pending object
```

A token granted for `report.csv` is rejected for `authorized_keys`. That is the
whole point of binding it.

## What this does not do

- **It does not sandbox.** A server that is already malicious still runs; the
  gate only withholds the calls it recognises as sensitive.
- **It does not verify the human.** Loopback only, no password: the threat
  model is a confused agent, not an attacker with a shell on the same machine.
- **It does not survive a client that ignores errors.** If your client treats a
  `-32001` as a retry, it will keep asking; that is a client bug, and visible.

## Token Vault

`demo/tokenvault.py` goes one step further than the gate: the agent never holds
the third-party token. A GitHub account is linked to the vault through the My
Account API, and the agent exchanges its own Auth0 refresh token for a GitHub
token at the moment of use.

```
1. discovery    issuer, endpoints
2. login        browser -> Auth0 -> refresh token + My Account API token
3. connect      My Account API asked to link a GitHub account
4. consent      browser -> GitHub -> connect_code on 127.0.0.1
5. complete     Auth0 stores the GitHub tokens in the vault
6. exchange     refresh token -> GitHub token, out of the vault
7. proof        that token really is GitHub's: GET /user
8. gated write  mcp-veto holds the write until a human approves it
```

Run against a live tenant and a real GitHub account:

```
5. connected account: cac_mK5dBHw7wq62GnafcNKTio
6. GitHub token: 40 chars, scope read:user repo, expires_in 28797
7. authenticated as: bryand410 (18 public repos)
8. created: https://github.com/bryand410/mcp-veto/issues/2
```

The GitHub token exists only in the process that uses it: it is never written to
disk and never printed.

Setup is written out in [SETUP-TOKENVAULT.md](SETUP-TOKENVAULT.md), with the six
errors that stood in the way and what each one actually meant.
`demo/auth0_setup.py` configures the tenant through the Management API instead
of the dashboard.

## Evidence

Run against `@modelcontextprotocol/server-filesystem@2.2.0` (real npm package,
real files on disk):

```
1. initialize            secure-filesystem-server 2.2.0
2. tools/list            16 tools announced
3. read_text_file        passes untouched
4. write_file            held; file absent from disk; approval URL printed
   after approval        file written
5. write_file (refused)  -32001; file still absent
```

```bash
python demo/live.py                 # wait for your click
python demo/live.py --auto-approve 2
```

9 tests, including two that spawn real processes and assert the file does not
exist while the call is pending. With the gate disabled, 7 of the 9 fail — the
bench is not vacuous.

## License

MIT
