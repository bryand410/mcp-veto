"""A minimal MCP stdio server used as the thing the gate protects.

It is deliberately real: `write_file` writes to disk. A test that only checks
that a message was not forwarded proves the gate is a filter; a test that
checks the file is absent proves it is a gate.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()

TOOLS = [
    {
        "name": "read_file",
        "description": "Read a text file from the workspace.",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
    },
    {
        "name": "write_file",
        "description": "Write text to a file in the workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
        },
    },
]


def _resolve(rel: str) -> Path:
    target = (ROOT / rel).resolve()
    if ROOT not in target.parents and target != ROOT:
        raise ValueError(f"path escapes the workspace: {rel}")
    return target


def _call(name: str, args: dict) -> dict:
    if name == "read_file":
        return {"content": [{"type": "text", "text": _resolve(args["path"]).read_text()}]}
    if name == "write_file":
        _resolve(args["path"]).write_text(args.get("content", ""))
        return {"content": [{"type": "text", "text": f"wrote {args['path']}"}]}
    raise ValueError(f"unknown tool: {name}")


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "id" not in msg:
            continue
        method = msg.get("method")
        if method == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fixture", "version": "0.1.0"},
            }
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            params = msg.get("params", {})
            try:
                result = _call(params.get("name", ""), params.get("arguments", {}))
            except Exception as exc:  # noqa: BLE001 - reported to the client
                sys.stdout.write(
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": msg["id"],
                            "error": {"code": -32602, "message": str(exc)},
                        }
                    )
                    + "\n"
                )
                sys.stdout.flush()
                continue
        else:
            result = {}
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
