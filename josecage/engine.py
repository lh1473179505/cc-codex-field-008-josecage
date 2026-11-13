"""JWS verification engine. Not implemented in this snapshot."""

from __future__ import annotations

from typing import Any

from josecage.keys import Keystore
from josecage.parse import CompactJws
from josecage.policy import Policy


def verify_jws(
    token: CompactJws,
    keystore: Keystore,
    policy: Policy,
    *,
    now: int,
) -> dict[str, Any]:
    raise NotImplementedError("verify_jws is not implemented in this snapshot")
