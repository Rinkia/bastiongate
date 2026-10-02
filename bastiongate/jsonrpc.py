"""Newline-delimited JSON-RPC framing for MCP stdio transport.

MCP stdio messages are one JSON object per line. These helpers read/write them
and classify a message so the proxy can route it.
"""

from __future__ import annotations

import base64
import binascii
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


_TEXT_MIME_MARKERS = ("json", "xml", "yaml", "javascript")
_MEDIA_MIME = ("image/", "audio/", "video/", "font/", "application/pdf", "application/zip")


def _is_text_mime(mime) -> bool:
    mime = str(mime or "").lower()
    return mime.startswith("text/") or any(m in mime for m in _TEXT_MIME_MARKERS)


def _blob_text(blob: str, mime) -> str | None:
    """A blob as the text a client could show the model. Text MIME types decode with
    replacement; any other non-media MIME (missing, octet-stream, a made-up type) counts
    only if it is valid UTF-8. Media (images, audio, pdf...) goes to the model as media,
    not text, and is never decoded (a big image must not trip the size fail-closed)."""
    low = str(mime or "").lower()
    if low.startswith(_MEDIA_MIME):
        return None
    try:
        raw = base64.b64decode(blob, validate=False)
    except (binascii.Error, ValueError):
        return None
    if _is_text_mime(mime):
        return raw.decode("utf-8", "replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def resource_texts(res) -> list[str]:
    """Text a model can read from one resource (an embedded `resource` or a
    `resources/read` contents entry): `uri`, `text`, and `blob` decoded (see _blob_text)."""
    if not isinstance(res, dict):
        return []
    out = [res[k] for k in ("uri", "text") if isinstance(res.get(k), str)]
    blob = res.get("blob")
    if isinstance(blob, str) and blob:
        text = _blob_text(blob, res.get("mimeType"))
        if text:
            out.append(text)
    return out


def _block_texts(block, resources: bool) -> list[str]:
    if not isinstance(block, dict):
        return []
    kind = block.get("type")
    if kind == "text":
        return [str(block.get("text", ""))]
    if not resources:
        return []
    if kind == "resource":
        return resource_texts(block.get("resource"))
    if kind == "resource_link":  # uri/name/title/description reach the model
        return [str(block[k]) for k in ("uri", "name", "title", "description") if isinstance(block.get(k), str)]
    return []


def result_text(msg: dict, *, resources: bool = True) -> str:
    """Every piece of text the model can read from a tools/call or resources/read
    result: text blocks and, with `resources`, embedded resources, resource links and
    `contents[]`. The one place every result scanner reads from."""
    result = msg.get("result")
    if not isinstance(result, dict):
        return ""
    parts = []
    blocks = result.get("content")
    for block in blocks if isinstance(blocks, list) else []:
        parts.extend(_block_texts(block, resources))
    contents = result.get("contents")
    if resources and isinstance(contents, list):
        for res in contents:
            parts.extend(resource_texts(res))
    return "\n".join(parts)


def tools_from_list_result(msg: dict) -> list[dict]:
    result = msg.get("result")
    if isinstance(result, dict) and isinstance(result.get("tools"), list):
        return result["tools"]
    return []
