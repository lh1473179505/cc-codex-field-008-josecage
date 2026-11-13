"""CLI. inspect already works; verify is the piece to implement."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from josecage.keys import KeystoreError, load_keystore
from josecage.parse import JwsParseError, parse_compact
from josecage.policy import PolicyError, load_policy


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="josecage")
    sub = p.add_subparsers(dest="cmd", required=True)

    ins = sub.add_parser("inspect", help="print the unverified header and payload")
    ins.add_argument("--token", required=True, help="compact JWS string, or @path to read one")

    ver = sub.add_parser("verify", help="fail-closed verification against a local keystore")
    ver.add_argument("--token", required=True, help="compact JWS string, or @path to read one")
    ver.add_argument("--keystore", required=True)
    ver.add_argument("--policy", required=True)
    ver.add_argument("--report", required=True)
    ver.add_argument(
        "--now",
        type=int,
        default=None,
        help="unix timestamp used for exp/nbf/iat (defaults to the current time)",
    )
    return p


def _read_token(value: str) -> str:
    if value.startswith("@"):
        return Path(value[1:]).read_text(encoding="utf-8").strip()
    path = Path(value)
    if path.is_file():
        return path.read_text(encoding="utf-8").strip()
    return value


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        raw = _read_token(args.token)
        token = parse_compact(raw)
    except (OSError, JwsParseError) as exc:
        print(f"failed to parse token: {exc}", file=sys.stderr)
        return 2

    if args.cmd == "inspect":
        print(json.dumps({
            "header": token.header,
            "payload": token.payload,
            "payload_b64": token.payload_b64,
            "signature_bytes": len(token.signature),
        }, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "verify":
        try:
            keystore = load_keystore(args.keystore)
            policy = load_policy(args.policy)
        except (KeystoreError, PolicyError, OSError) as exc:
            print(f"failed to load keystore or policy: {exc}", file=sys.stderr)
            return 2
        now = args.now if args.now is not None else int(time.time())
        from josecage.engine import verify_jws

        try:
            report = verify_jws(token, keystore, policy, now=now)
        except NotImplementedError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        except Exception as exc:
            print(f"verify failed unexpectedly: {exc}", file=sys.stderr)
            return 2
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        decision = str(report.get("decision", "")).lower()
        if decision == "allow":
            return 0
        if decision == "deny":
            return 1
        print("report is missing a decision of allow or deny", file=sys.stderr)
        return 2

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
