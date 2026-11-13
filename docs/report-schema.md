# Report schema

`verify` always writes a JSON object to `--report` when it can produce a decision of `allow` or `deny`.

```json
{
  "decision": "allow",
  "reason_codes": [],
  "alg": "HS256",
  "kid": "hs-main",
  "typ": "JWT",
  "claims": {
    "iss": "https://auth.josecage.example",
    "aud": "josecage-api",
    "sub": "user-42",
    "exp": 1920680000,
    "nbf": 1762999940,
    "iat": 1763000000
  },
  "header_parameters": ["alg", "kid", "typ"]
}
```

- `decision` is `allow` or `deny`.
- `reason_codes` is an array of strings. It is empty on `allow`. On `deny` it contains one or more codes from `docs/verify-rules.md` (`blocked_alg`, `alg_key_mismatch`, `missing_kid`, `unknown_kid`, `blocked_kid`, `remote_key_ref`, `embedded_jwk`, `ununderstood_crit`, `blocked_typ`, `missing_claim`, `expired`, `not_yet_valid`, `invalid_iat`, `blocked_iss`, `blocked_aud`, `bad_signature`). If several checks fail, include all that were evaluated; checks may stop after the first definite deny, in which case only the codes reached so far appear.
- `alg`, `kid`, and `typ` are copied from the unverified header when present, otherwise `null`.
- `claims` is the parsed payload object when the payload is a JSON object, otherwise `null`.
- `header_parameters` lists the header keys in the order they appeared after JSON parse (implementation-defined order is acceptable).
