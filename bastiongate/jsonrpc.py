"""Newline-delimited JSON-RPC framing for MCP stdio transport.

MCP stdio messages are one JSON object per line. These helpers read/write them
and classify a message so the proxy can route it.
"""

from __future__ import annotations

import json
from typing import IO, Iterator


def read_messages(stream: IO[str]) -> Iterator[dict]:
    """Yield each JSON-RPC message from a text stream until EOF.

    Non-JSON lines (a server logging to stdout) are skipped, not fatal.
    """
    for line in stream:
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def write_message(stream: IO[str], msg: dict) -> None:
    stream.write(json.dumps(msg) + "\n")
    stream.flush()


def method_of(msg: dict) -> str | None:
    return msg.get("method")


def is_request(msg: dict) -> bool:
    return "method" in msg and "id" in msg


def is_response(msg: dict) -> bool:
    return "id" in msg and ("result" in msg or "error" in msg)


def error_response(mid, code: int, message: str, data=None) -> dict:
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": mid, "error": err}


# tool-call results carry content blocks; pull their text out for scanning
def result_text(msg: dict) -> str:
    result = msg.get("result")
    if not isinstance(result, dict):
        return ""
    parts = []
    for block in result.get("content", []) or []:
        if isinstance(block, dict) and block.get("type") == "text":
            parts.append(str(block.get("text", "")))
    return "\n".join(parts)


def tools_from_list_result(msg: dict) -> list[dict]:
    result = msg.get("result")
    if isinstance(result, dict) and isinstance(result.get("tools"), list):
        return result["tools"]
    return []
