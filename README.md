# josecage

A small fail-closed verifier for compact JWS / JWT tokens. Parsing, the local keystore, and the policy file already work. `inspect` can print an unverified header and payload. `verify` enforces the rules in `docs/verify-rules.md` and writes the report described in `docs/report-schema.md`.

This tool is meant to sit in front of an internal API gateway: tokens are only accepted when the signature, the key binding, and the registered claims all survive a conservative policy. The verifier must not take keys from the token itself, and it must not treat a public RSA key as an HMAC secret.

## Requirements

- Python 3.11+
- The `cryptography` package (see `requirements.txt`) for RSA signature checks
- No containers, no network key lookup (`jku` / `x5u` / `x5c` are not a key source)

## Already working

```bash
python -m josecage inspect --token fixtures/tokens/valid-hs256.jwt
```

`--token` may be a compact JWS string, a path, or `@path`.

Keystore and policy shapes are in `fixtures/keystore.json` and `fixtures/policy.json`. Verification rules are in `docs/verify-rules.md`. The report object is in `docs/report-schema.md`.

## Intended CLI

```bash
python -m josecage verify \
  --token fixtures/tokens/valid-hs256.jwt \
  --keystore fixtures/keystore.json \
  --policy fixtures/policy.json \
  --report /tmp/josecage-report.json \
  --now 1763000000
```

Parameter names are fixed in `josecage/__main__.py`. Keep them.

`--now` is a Unix timestamp used for `exp` / `nbf` / `iat`. When it is omitted, the current time is used. The public fixtures were issued around `1763000000`.

## Layout

- `josecage/parse.py` — compact JWS parsing
- `josecage/keys.py` — keystore loader (`oct` HMAC secrets and RSA public keys)
- `josecage/policy.py` — policy loader
- `josecage/engine.py` — `verify_jws`, the fail-closed verification engine
- `fixtures/tokens/` — a valid HS256 token, a valid RS256 token, an expired token, and an `alg=none` token
