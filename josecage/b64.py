"""URL-safe base64 without padding, as used by compact JWS."""

from __future__ import annotations


def b64url_encode(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    import base64
    import re

    if not isinstance(text, str):
        raise ValueError("base64url input must be a string")
    if text == "":
        return b""
    if not re.fullmatch(r"[A-Za-z0-9_-]+", text):
        raise ValueError("base64url input contains invalid characters")
    pad = "=" * ((4 - len(text) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(text + pad)
    except Exception as exc:
        raise ValueError("invalid base64url") from exc
