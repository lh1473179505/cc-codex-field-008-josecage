"""Load a local keystore. Keys never come from the token alone."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class KeystoreError(ValueError):
    pass


@dataclass
class HmacKey:
    kid: str
    kty: str
    alg_family: str
    secret: bytes


@dataclass
class RsaPublicKey:
    kid: str
    kty: str
    alg_family: str
    pem: str
    n: int
    e: int


Key = HmacKey | RsaPublicKey


@dataclass
class Keystore:
    keys: dict[str, Key]

    def get(self, kid: str) -> Key | None:
        return self.keys.get(kid)

    def hmac_keys(self) -> list[HmacKey]:
        return [k for k in self.keys.values() if isinstance(k, HmacKey)]

    def rsa_keys(self) -> list[RsaPublicKey]:
        return [k for k in self.keys.values() if isinstance(k, RsaPublicKey)]


def _b64url_to_int(text: str) -> int:
    from josecage.b64 import b64url_decode

    raw = b64url_decode(text)
    return int.from_bytes(raw, "big")


def load_keystore(path: str | Path) -> Keystore:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise KeystoreError(f"failed to read keystore: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
        raise KeystoreError("keystore must be an object with a keys array")
    keys: dict[str, Key] = {}
    for item in data["keys"]:
        if not isinstance(item, dict):
            raise KeystoreError("each key must be an object")
        kid = item.get("kid")
        kty = item.get("kty")
        if not isinstance(kid, str) or kid == "":
            raise KeystoreError("key is missing kid")
        if kid in keys:
            raise KeystoreError(f"duplicate kid: {kid}")
        if kty == "oct":
            from josecage.b64 import b64url_decode

            k = item.get("k")
            if not isinstance(k, str):
                raise KeystoreError(f"oct key {kid} missing k")
            keys[kid] = HmacKey(kid=kid, kty="oct", alg_family="HS", secret=b64url_decode(k))
        elif kty == "RSA":
            pem = item.get("pem")
            n = item.get("n")
            e = item.get("e")
            if not isinstance(pem, str) or not isinstance(n, str) or not isinstance(e, str):
                raise KeystoreError(f"RSA key {kid} must include pem, n, and e")
            keys[kid] = RsaPublicKey(
                kid=kid,
                kty="RSA",
                alg_family="RS",
                pem=pem,
                n=_b64url_to_int(n),
                e=_b64url_to_int(e),
            )
        else:
            raise KeystoreError(f"unsupported kty for {kid}: {kty}")
    return Keystore(keys=keys)
