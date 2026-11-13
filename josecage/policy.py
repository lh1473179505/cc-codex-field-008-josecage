"""Verification policy loader."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class PolicyError(ValueError):
    pass


@dataclass
class Policy:
    allowed_algs: set[str]
    allowed_issuers: set[str]
    allowed_audiences: set[str]
    allowed_typs: set[str]
    required_claims: set[str]
    leeway_seconds: int
    understood_headers: set[str]
    allow_embedded_jwk: bool
    require_kid: bool
    raw: dict[str, Any] = field(default_factory=dict)


def load_policy(path: str | Path) -> Policy:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise PolicyError(f"failed to read policy: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError("policy must be a JSON object")

    def _strset(name: str, default: list[str] | None = None) -> set[str]:
        val = data.get(name, default if default is not None else [])
        if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
            raise PolicyError(f"{name} must be an array of strings")
        return set(val)

    leeway = data.get("leeway_seconds", 0)
    if not isinstance(leeway, int) or isinstance(leeway, bool) or leeway < 0:
        raise PolicyError("leeway_seconds must be a non-negative integer")
    return Policy(
        allowed_algs=_strset("allowed_algs"),
        allowed_issuers=_strset("allowed_issuers"),
        allowed_audiences=_strset("allowed_audiences"),
        allowed_typs=_strset("allowed_typs", ["JWT"]),
        required_claims=_strset("required_claims", ["exp", "iss", "aud"]),
        leeway_seconds=leeway,
        understood_headers=_strset("understood_headers", ["alg", "kid", "typ"]),
        allow_embedded_jwk=bool(data.get("allow_embedded_jwk", False)),
        require_kid=bool(data.get("require_kid", True)),
        raw=data,
    )
