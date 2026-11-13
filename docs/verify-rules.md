# Verification rules

`verify` is fail-closed. If a check does not unambiguously succeed, the decision is `deny`. Implementation faults (unreadable keystore, unreadable policy, or a token that cannot even be parsed as compact JWS) are not a deny report; they are a process error.

## Key binding

- The `alg` header never selects a key by itself, and it never overrides the key type recorded in the keystore.
- HMAC algorithms (`HS256`, `HS384`, `HS512`) may only be verified with an `oct` key's secret. RSA algorithms (`RS256`, `RS384`, `RS512`) may only be verified with an `RSA` public key. A mismatch is `alg_key_mismatch`.
- In particular, if the header says `HS256` and `kid` points at `rs-main`, deny. Do not use the RSA PEM bytes, modulus, or any other RSA material as an HMAC secret.
- `kid` is a literal keystore lookup. If `require_kid` is true (the default policy), a missing `kid` is `missing_kid`. A `kid` that is not in the keystore is `unknown_kid`.
- A `kid` containing `/`, `\`, `..`, a NUL byte, a colon-slash URL scheme, or any path component is `blocked_kid`. Do not try to treat `kid` as a file path or URL even if it happens to look like one.

## Algorithms and header parameters

- An missing, empty, or `none` / `NONE` (any ASCII case) algorithm is `blocked_alg`.
- An algorithm not listed in `allowed_algs` is `blocked_alg`. The public policy allows only `HS256` and `RS256`.
- `jku`, `x5u`, and `x5c` are never used as a key source. If any of them is present, deny with `remote_key_ref`.
- An embedded `jwk` header is `embedded_jwk` unless `allow_embedded_jwk` is true *and* the embedded key's thumbprint (JWK SHA-256 thumbprint per RFC 7638, over the required members for that `kty`) matches a key already in the keystore *and* that key's type is compatible with `alg`. The public policy sets `allow_embedded_jwk` to false, so any `jwk` member is deny.
- If `crit` is present, it must be an array of strings. Every entry must also appear in `understood_headers`, and the implementation must actually enforce that header. Otherwise deny with `ununderstood_crit`. The public policy understands `alg`, `kid`, and `typ` only.
- If `typ` is present, compare it case-sensitively after stripping a leading `application/` prefix, and require it to be in `allowed_typs`. The public policy allows only `JWT`. A typ of `JOSE`, `jwt`, or `JWT ` (trailing space) is `blocked_typ`.

## Registered claims

- Claims listed in `required_claims` must be present. The public policy requires `exp`, `iss`, `aud`, and `sub`.
- `exp` is a numeric Unix timestamp. Deny `expired` when `exp <= now - leeway_seconds`.
- `nbf`, when present, is numeric. Deny `not_yet_valid` when `nbf > now + leeway_seconds`.
- `iat`, when present, is numeric. Deny `invalid_iat` when `iat > now + leeway_seconds`.
- `iss` must be an exact string match against `allowed_issuers`.
- `aud` may be a string or an array of strings. At least one value must be an exact match against `allowed_audiences`. No prefix or suffix matching.
- `sub` must be a non-empty string when required.
- Numeric date claims must be numbers, not numeric strings.

## Signatures

- Build the signing input from the original header and payload segments (`header_b64 + "." + payload_b64`), not from a re-encoded JSON object.
- `HS256` / `HS384` / `HS512` use HMAC with SHA-256 / SHA-384 / SHA-512 and a constant-time comparison.
- `RS256` / `RS384` / `RS512` use RSASSA-PKCS1-v1_5 with the matching SHA-2 hash, over the same signing input.
- A bad signature is `bad_signature`.
- Do not add a JWT library as a dependency. Reuse `parse_compact`, `load_keystore`, and `load_policy`.

## Exit status

- `allow` → exit 0
- `deny` → exit 1
- Parse errors, keystore/policy load errors, or implementation faults → exit 2, and do not write a report that claims `allow`.
