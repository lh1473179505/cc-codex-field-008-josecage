"""Fail-closed compact JWS verification engine."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from josecage.b64 import b64url_encode
from josecage.keys import HmacKey, Keystore, RsaPublicKey
from josecage.parse import CompactJws
from josecage.policy import Policy

_HMAC_HASHES = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
_RSA_HASHES = {"RS256": "SHA256", "RS384": "SHA384", "RS512": "SHA512"}
_REMOTE_KEY_HEADERS = ("jku", "x5u", "x5c")
_ENFORCED_HEADERS = {"alg", "kid", "typ"}


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _kid_is_blocked(kid: str) -> bool:
    return (
        "\x00" in kid
        or "/" in kid
        or "\\" in kid
        or ".." in kid
        or "://" in kid
    )


def _int_to_b64url(value: int) -> str:
    length = max(1, (value.bit_length() + 7) // 8)
    return b64url_encode(value.to_bytes(length, "big"))


def _jwk_thumbprint(members: dict[str, str]) -> str:
    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return b64url_encode(hashlib.sha256(canonical).digest())


def _key_thumbprint(key: HmacKey | RsaPublicKey) -> str:
    if isinstance(key, HmacKey):
        return _jwk_thumbprint({"k": b64url_encode(key.secret), "kty": "oct"})
    return _jwk_thumbprint(
        {"e": _int_to_b64url(key.e), "kty": "RSA", "n": _int_to_b64url(key.n)}
    )


def _embedded_jwk_key(token: CompactJws, keystore: Keystore) -> HmacKey | RsaPublicKey | None:
    jwk = token.header.get("jwk")
    if not isinstance(jwk, dict):
        return None
    kty = jwk.get("kty")
    if kty == "oct":
        k = jwk.get("k")
        if not isinstance(k, str):
            return None
        thumb = _jwk_thumbprint({"k": k, "kty": "oct"})
    elif kty == "RSA":
        n = jwk.get("n")
        e = jwk.get("e")
        if not isinstance(n, str) or not isinstance(e, str):
            return None
        thumb = _jwk_thumbprint({"e": e, "kty": "RSA", "n": n})
    else:
        return None
    for key in keystore.keys.values():
        if _key_thumbprint(key) == thumb:
            return key
    return None


def _verify_signature(key: HmacKey | RsaPublicKey, alg: str, token: CompactJws) -> bool:
    if isinstance(key, HmacKey):
        digestmod = _HMAC_HASHES[alg]
        expected = hmac.new(key.secret, token.signing_input, digestmod).digest()
        return hmac.compare_digest(expected, token.signature)
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    public_key = serialization.load_pem_public_key(key.pem.encode("utf-8"))
    hash_alg = getattr(hashes, _RSA_HASHES[alg])()
    try:
        public_key.verify(token.signature, token.signing_input, padding.PKCS1v15(), hash_alg)
    except InvalidSignature:
        return False
    return True


def verify_jws(
    token: CompactJws,
    keystore: Keystore,
    policy: Policy,
    *,
    now: int,
) -> dict[str, Any]:
    header = token.header
    payload = token.payload if isinstance(token.payload, dict) else None
    reasons: list[str] = []

    report: dict[str, Any] = {
        "decision": "deny",
        "reason_codes": reasons,
        "alg": header.get("alg") if isinstance(header.get("alg"), str) else None,
        "kid": header.get("kid") if isinstance(header.get("kid"), str) else None,
        "typ": header.get("typ") if isinstance(header.get("typ"), str) else None,
        "claims": payload,
        "header_parameters": list(header.keys()),
    }

    alg = header.get("alg")
    alg_ok = (
        isinstance(alg, str)
        and alg != ""
        and alg.lower() != "none"
        and alg in policy.allowed_algs
        and (alg in _HMAC_HASHES or alg in _RSA_HASHES)
    )
    if not alg_ok:
        reasons.append("blocked_alg")

    if any(name in header for name in _REMOTE_KEY_HEADERS):
        reasons.append("remote_key_ref")

    embedded_key: HmacKey | RsaPublicKey | None = None
    if "jwk" in header:
        if policy.allow_embedded_jwk:
            embedded_key = _embedded_jwk_key(token, keystore)
            if embedded_key is None:
                reasons.append("embedded_jwk")
        else:
            reasons.append("embedded_jwk")

    if "crit" in header:
        crit = header["crit"]
        if (
            not isinstance(crit, list)
            or not all(isinstance(item, str) for item in crit)
            or any(
                item not in policy.understood_headers
                or item not in _ENFORCED_HEADERS
                or item not in header
                for item in crit
            )
        ):
            reasons.append("ununderstood_crit")

    typ = header.get("typ")
    if typ is not None:
        if not isinstance(typ, str):
            reasons.append("blocked_typ")
        else:
            stripped = typ[len("application/"):] if typ.startswith("application/") else typ
            if stripped not in policy.allowed_typs:
                reasons.append("blocked_typ")

    key: HmacKey | RsaPublicKey | None = embedded_key
    kid = header.get("kid")
    if embedded_key is None:
        if kid is None:
            if policy.require_kid:
                reasons.append("missing_kid")
        elif not isinstance(kid, str) or kid == "":
            reasons.append("missing_kid")
        elif _kid_is_blocked(kid):
            reasons.append("blocked_kid")
        else:
            key = keystore.get(kid)
            if key is None:
                reasons.append("unknown_kid")

    if reasons:
        return report

    if key is not None and isinstance(alg, str) and alg_ok:
        if alg in _HMAC_HASHES and not isinstance(key, HmacKey):
            reasons.append("alg_key_mismatch")
        elif alg in _RSA_HASHES and not isinstance(key, RsaPublicKey):
            reasons.append("alg_key_mismatch")
        if reasons:
            return report

    if payload is None:
        reasons.append("missing_claim")
        return report

    for name in sorted(policy.required_claims):
        if name not in payload:
            reasons.append("missing_claim")
            break

    leeway = policy.leeway_seconds
    if "exp" in payload:
        exp = payload["exp"]
        if not _is_number(exp):
            reasons.append("missing_claim")
        elif exp <= now - leeway:
            reasons.append("expired")
    if "nbf" in payload:
        nbf = payload["nbf"]
        if not _is_number(nbf):
            reasons.append("not_yet_valid")
        elif nbf > now + leeway:
            reasons.append("not_yet_valid")
    if "iat" in payload:
        iat = payload["iat"]
        if not _is_number(iat):
            reasons.append("invalid_iat")
        elif iat > now + leeway:
            reasons.append("invalid_iat")

    if "iss" in payload:
        iss = payload["iss"]
        if not isinstance(iss, str) or iss not in policy.allowed_issuers:
            reasons.append("blocked_iss")
    if "aud" in payload:
        aud = payload["aud"]
        if isinstance(aud, str):
            aud_values = [aud]
        elif isinstance(aud, list) and all(isinstance(item, str) for item in aud):
            aud_values = aud
        else:
            aud_values = []
        if not any(value in policy.allowed_audiences for value in aud_values):
            reasons.append("blocked_aud")
    if "sub" in policy.required_claims and "sub" in payload:
        sub = payload["sub"]
        if not isinstance(sub, str) or sub == "":
            reasons.append("missing_claim")

    if reasons:
        return report

    if key is None or not _verify_signature(key, alg, token):
        reasons.append("bad_signature")
        return report

    report["decision"] = "allow"
    return report
