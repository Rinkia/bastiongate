"""Newline-delimited JSON-RPC framing for MCP stdio transport.

MCP stdio messages are one JSON object per line. These helpers read/write them
and classify a message so the proxy can route it.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import urllib.parse
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
_URLSAFE = str.maketrans("-_", "+/")
_NOT_B64 = re.compile(r"[^A-Za-z0-9+/]+")


def _is_text_mime(mime) -> bool:
    mime = str(mime or "").lower()
    return mime.startswith("text/") or any(m in mime for m in _TEXT_MIME_MARKERS)


def _blob_text(blob: str, mime) -> str | None:
    """A blob as the text a client could show the model. Text MIME types decode with
    replacement; any other non-media MIME (missing, octet-stream, a made-up type) counts
    only if it is valid UTF-8. Media (images, audio, pdf...) goes to the model as media,
    not text, and is never decoded (a big image must not trip the size fail-closed)."""
    low = str(mime or "").lower()
    if low.startswith(_MEDIA_MIME) and "xml" not in low:  # SVG is text a client may pass on
        return None
    try:
        b64 = _NOT_B64.sub("", blob.translate(_URLSAFE))  # base64url too; whitespace dropped
        raw = base64.b64decode(b64 + "=" * (-len(b64) % 4))
    except (binascii.Error, ValueError):
        return None
    if _is_text_mime(mime):
        return raw.decode("utf-8", "replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _uri(uri: str) -> str:
    """A URI as the model may read it: percent-escapes decoded too (both forms scanned)."""
    decoded = urllib.parse.unquote(uri)
    return uri if decoded == uri else f"{uri}\n{decoded}"


def blob_text(res: dict) -> str | None:
    """The text inside a resource's blob, as _blob_text decodes it, or None."""
    blob = res.get("blob")
    return _blob_text(blob, res.get("mimeType")) if isinstance(blob, str) and blob else None


def resource_texts(res) -> list[str]:
    """Text a model can read from one resource (an embedded `resource` or a
    `resources/read` contents entry): `uri`, `text`, and `blob` decoded (see _blob_text)."""
    if not isinstance(res, dict):
        return []
    out = [_uri(res["uri"])] if isinstance(res.get("uri"), str) else []
    if isinstance(res.get("text"), str):
        out.append(res["text"])
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
        return [_uri(block[k]) if k == "uri" else block[k]
                for k in ("uri", "name", "title", "description") if isinstance(block.get(k), str)]
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
    messages = result.get("messages")  # prompts/get
    if isinstance(result.get("description"), str):
        parts.append(result["description"])
    for m in messages if isinstance(messages, list) else []:
        content = m.get("content") if isinstance(m, dict) else None
        for block in content if isinstance(content, list) else [content]:
            parts.extend(_block_texts(block, resources))
    return "\n".join(parts)


def tools_from_list_result(msg: dict) -> list[dict]:
    result = msg.get("result")
    if isinstance(result, dict) and isinstance(result.get("tools"), list):
        return result["tools"]
    return []
