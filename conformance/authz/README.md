# Authorization-seam conformance vectors

Wire vectors for `gwr:authz-request:v1` and `ag.docket-issuance:v1`. This repository is
the authoritative home for both contracts; the producer (an upstream authorization
office) and the consumer (this runtime's intake) implement them independently and each
verifies the other's artifacts against these files.

`request.json` and `issuance.json` were produced by a real end-to-end run
(`docs/vertical-01.md`); every `issuance-*.json` derivative is that issuance with one
protected field altered, so the signature no longer covers the body. `trust.json` holds
only the issuing **public** key — no private key material exists in this directory.
`DIGESTS.txt` records the SHA-256 of every file.

Note that the request and issuance name a real historical attempt and basis, so the
positive vectors verify as *records* (schema, authenticity, internal binding) but will
refuse binding against any other store's attempt — which is the point: a consumer must
compare against its own stored attempt, never against the record's echoes.

| vector | expected consumer outcome |
|---|---|
| `request.json` | decodes as the supported request schema |
| `request-changed.json` | a different request: any issuance naming the original no longer matches these bytes |
| `request-unsupported-effect-class.json` | producer refuses (`unsupported effect class`); no issuance |
| `issuance.json` | schema, trusted issuer, and signature verify; binding checked against the consumer's own attempt |
| `issuance-changed-prepared-digest.json` | `authentication_failed` (protected field altered) |
| `issuance-changed-ag-digest.json` | `authentication_failed` |
| `issuance-changed-raw-digest.json` | `authentication_failed` |
| `issuance-changed-scope.json` | `authentication_failed` |
| `issuance-changed-actor.json` | `authentication_failed` |
| `issuance-changed-premise.json` | `authentication_failed` — premises are protected |
| `issuance-changed-residual.json` | `authentication_failed` — residual status is protected |
| `issuance-expired.json` | `authentication_failed` (the derivative is tampered); an *authentically* expired issuance refuses `expired` |
| `issuance-not-admitted.json` | `authentication_failed`; an authentic non-admit refuses `not_admitted` |
| `issuance-unknown-issuer.json` | `untrusted_issuer` |
| `issuance-bad-authentication.json` | `authentication_failed` |
| `issuance-unsupported-schema.json` | `unsupported_schema` |
| `refusal-object.json` | `malformed_issuance` — a refusal is never an issuance |

Every refusal mints no standing, creates no reservation or dispatch, and mutates no
repository. Duplicate intake of `issuance.json` is idempotent; the same issuance
identity carrying a different signed body is a substitution refusal; and one issuance
cannot mint standing twice or for two attempts — those laws are exercised in
`crates/gwr-local/tests/authz_intake.rs` and, on the producer side, in the upstream
office's own suite.
