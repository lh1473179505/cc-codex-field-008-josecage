"""Parse compact JWS (three dot-separated segments) without verifying."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from josecage.b64 import b64url_decode


class JwsParseError(ValueError):
    pass


@dataclass
class CompactJws:
    raw: str
    header_b64: str
    payload_b64: str
    signature_b64: str
    header: dict[str, Any] = field(default_factory=dict)
    payload: dict[str, Any] | None = None
    payload_bytes: bytes = b""
    signature: bytes = b""
    signing_input: bytes = b""


def parse_compact(token: str) -> CompactJws:
    if not isinstance(token, str):
        raise JwsParseError("token must be a string")
    token = token.strip()
    if token.startswith("ey") is False and token == "":
        raise JwsParseError("empty token")
    if token.count(".") != 2:
        raise JwsParseError("compact JWS must have exactly three segments")
    h, p, s = token.split(".")
    if h == "" or p == "":
        raise JwsParseError("header and payload segments must be non-empty")
    try:
        header_bytes = b64url_decode(h)
        payload_bytes = b64url_decode(p)
        signature = b64url_decode(s) if s != "" else b""
    except ValueError as exc:
        raise JwsParseError(str(exc)) from exc
    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except Exception as exc:
        raise JwsParseError("header is not UTF-8 JSON") from exc
    if not isinstance(header, dict):
        raise JwsParseError("header must be a JSON object")
    payload_obj: dict[str, Any] | None
    try:
        loaded = json.loads(payload_bytes.decode("utf-8"))
        payload_obj = loaded if isinstance(loaded, dict) else None
    except Exception:
        payload_obj = None
    return CompactJws(
        raw=token,
        header_b64=h,
        payload_b64=p,
        signature_b64=s,
        header=header,
        payload=payload_obj,
        payload_bytes=payload_bytes,
        signature=signature,
        signing_input=f"{h}.{p}".encode("ascii"),
    )
