# Security Policy

## Reporting Vulnerabilities

**Do not file security issues as public GitHub Issues.**

Use [GitHub's private vulnerability reporting](https://github.com/unpingable/docket/security/advisories/new)
or email the maintainer directly.

## Response Time

Best-effort. This is a solo-maintained project with no SLA. Expect acknowledgment within a
week for genuine vulnerabilities; fixes depend on severity and complexity.

## Scope

**In scope:** anything that lets an accepted execution apply an unadmitted effect, assert a
false world-state verdict, bypass or replay authority, or lose an acknowledged effect
outside recoverable settlement. Concretely: the attempt lifecycle and its successor
relation, the four bridges, standing and reservation consumption, the store's transaction
and transition validation, the Git broker's path authorization and atomic ref transition,
recovery-fact binding and verdict derivation, and the standing-token codec.

**Out of scope for v0.1.0**, because the runtime does not claim them:

- **Same-UID confinement.** Providers and the broker are trusted code inside the host and
  same-UID security domain. The runtime claims only that it hands providers no authority
  material and does not place their workspace adjacent to it. A provider reading the state
  directory by absolute path is a known, documented consequence, not a vulnerability
  against these claims.
- **The broker binary as a privilege boundary.** Its envelope is unauthenticated, but
  anything able to run it could run `git update-ref` directly.
- **External mutation of the governed target ref.** `ProvenNotCommitted` is valid only
  under `ExclusiveRefCustody`; violating that premise produces an unsound verdict by
  construction, which is documented and carries an executable boundary specimen.
- **Clock rollback.** Expiry is judged against runtime clock readings; monotone time is an
  environment assumption.
- The models being constrained, third-party dependencies, and deployment infrastructure.

Reports that turn on these boundaries are still welcome as **documentation issues** if the
claims are stated inaccurately anywhere — a claim that overstates what the runtime enforces
is itself a defect worth fixing.

## Context

This is a governance and evidence system, not a security product. It defends against
fabricated claims, replayed authority, lost effects, and false settlement verdicts, under
an explicitly stated trust model. Read
[`docs/governed-runtime/trust-model.md`](docs/governed-runtime/trust-model.md) before
assessing whether something is in scope: the assumptions are deliberately written down
rather than left implicit, and several things a reader might expect to be enforced are
recorded there as premises instead.

## Disclosure

Coordinated disclosure. If you report a vulnerability, we will work with you on timeline
and credit. No bounties (solo project, no budget), but you will be credited in the fix
commit and release notes.
