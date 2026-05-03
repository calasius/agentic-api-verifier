#!/usr/bin/env python3
"""MCP stdio bridge: routes tool calls into the apisec-sandbox container.

Speaks JSON-RPC 2.0 over stdin/stdout (the MCP stdio transport). When the
client (opencode) calls the `bash` tool, this process runs the command via
`podman exec <container> bash -c '<cmd>'` and streams the captured output
back as the tool result.

Environment:
  SANDBOX_CONTAINER  name of the running podman container (default: apisec-sandbox)
  SANDBOX_RUNTIME    container runtime binary (default: podman)
  SANDBOX_TIMEOUT    per-command timeout in seconds (default: 120)
  SANDBOX_OUT_LIMIT  max bytes of stdout/stderr to return (default: 65536)
"""
from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from typing import Any

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "apisec-sandbox"
SERVER_VERSION = "0.1.0"

CONTAINER = os.environ.get("SANDBOX_CONTAINER", "apisec-sandbox")
RUNTIME = os.environ.get("SANDBOX_RUNTIME", "podman")
TIMEOUT = int(os.environ.get("SANDBOX_TIMEOUT", "120"))
OUT_LIMIT = int(os.environ.get("SANDBOX_OUT_LIMIT", "65536"))


def write_message(msg: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(msg, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def read_message() -> dict[str, Any] | None:
    line = sys.stdin.readline()
    if not line:
        return None
    line = line.strip()
    if not line:
        return read_message()
    return json.loads(line)


def truncate(text: str) -> str:
    if len(text) <= OUT_LIMIT:
        return text
    head = text[: OUT_LIMIT // 2]
    tail = text[-OUT_LIMIT // 2 :]
    return f"{head}\n... [truncated {len(text) - OUT_LIMIT} bytes] ...\n{tail}"


def exec_in_container(command: str) -> dict[str, Any]:
    cmd = [RUNTIME, "exec", CONTAINER, "bash", "-lc", command]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            check=False,
        )
    except FileNotFoundError:
        return {
            "isError": True,
            "content": [
                {
                    "type": "text",
                    "text": (
                        f"Container runtime '{RUNTIME}' is not on PATH. "
                        "Install podman/docker or set SANDBOX_RUNTIME."
                    ),
                }
            ],
        }
    except subprocess.TimeoutExpired:
        return {
            "isError": True,
            "content": [
                {
                    "type": "text",
                    "text": f"Command timed out after {TIMEOUT}s: {command[:200]}",
                }
            ],
        }

    stdout = truncate(proc.stdout)
    stderr = truncate(proc.stderr)
    body = []
    if stdout:
        body.append(f"STDOUT:\n{stdout}")
    if stderr:
        body.append(f"STDERR:\n{stderr}")
    body.append(f"EXIT: {proc.returncode}")
    return {
        "isError": proc.returncode != 0,
        "content": [{"type": "text", "text": "\n\n".join(body)}],
    }


TOOLS = [
    {
        "name": "bash",
        "description": (
            "Execute a bash command inside the isolated apisec-sandbox "
            "container. The container has the toolkit listed in "
            "/sandbox/TOOLS.md (curl, httpie, jwt_tool, sqlmap, ffuf, "
            "python httpx/pyjwt, jq, etc). The project source tree is "
            "mounted read-only at /workspace. Use /sandbox for any writable "
            "scratch (exploit scripts, attacker-controlled servers, "
            "captured responses). Network egress is restricted to the "
            "target API. The host machine is reachable as "
            "host.containers.internal. Output is truncated at 64 KB."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Bash command to run inside the container.",
                }
            },
            "required": ["command"],
        },
    }
]


def handle_initialize(_params: dict[str, Any]) -> dict[str, Any]:
    return {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {"tools": {"listChanged": False}},
        "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
    }


def handle_tools_list(_params: dict[str, Any]) -> dict[str, Any]:
    return {"tools": TOOLS}


def handle_tools_call(params: dict[str, Any]) -> dict[str, Any]:
    name = params.get("name", "")
    args = params.get("arguments", {}) or {}
    if name == "bash":
        cmd = args.get("command", "")
        if not isinstance(cmd, str) or not cmd.strip():
            return {
                "isError": True,
                "content": [{"type": "text", "text": "Missing 'command' argument."}],
            }
        return exec_in_container(cmd)
    return {
        "isError": True,
        "content": [{"type": "text", "text": f"Unknown tool: {name}"}],
    }


HANDLERS = {
    "initialize": handle_initialize,
    "tools/list": handle_tools_list,
    "tools/call": handle_tools_call,
    "ping": lambda _p: {},
}


def main() -> int:
    while True:
        try:
            msg = read_message()
        except json.JSONDecodeError as exc:
            sys.stderr.write(f"apisec-bridge: bad JSON: {exc}\n")
            continue
        if msg is None:
            return 0

        method = msg.get("method", "")
        msg_id = msg.get("id")

        # Notifications (no id) — do not respond.
        if msg_id is None:
            continue

        handler = HANDLERS.get(method)
        if handler is None:
            write_message(
                {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32601, "message": f"Method not found: {method}"},
                }
            )
            continue

        try:
            result = handler(msg.get("params", {}) or {})
            write_message({"jsonrpc": "2.0", "id": msg_id, "result": result})
        except Exception as exc:  # pragma: no cover
            write_message(
                {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32603, "message": f"{type(exc).__name__}: {exc}"},
                }
            )


if __name__ == "__main__":
    sys.exit(main())
