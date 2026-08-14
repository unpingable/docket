# Canonical governed repair R2 custody correction basis

Status: **self-produced development correction; operational qualification is
`not_assessed`; awaiting independent review after completion**.

R2 corrects the rejected R1 development custody seam under external human
development authorization.  Docket did not authorize or independently review
its own correction.  The NQ specimens remain immutable historical fixtures,
not Docket custody or present repair authority.

## AG/Docket correspondence

AG owns canonical governance and issuance semantics.  Docket owns custody,
attempts, cumulative reported-effect history, immutable checkpoint
verification, and sealed results.  AG owns the versioned cross-repository
contract and producer corpus; this repository pins and consumes the same bytes.
Release conformance also sends actual AG product issuance bytes through actual
Docket intake.

| Input | Docket validation | Refusal point |
| --- | --- | --- |
| signed `AgIssuanceV2` | strict canonical envelope/body and authentication | before Standing/custody |
| structured scope and claimed identity | AG RFC-8785 domain identity reproduced exactly | before Standing/custody |
| starting checkpoint | exact optional-member spelling and configured verifier | before Standing/custody and again before reconciliation |
| requested delta | semantic shape plus AG RFC-8785 identity | seal, database read, restart, replay |
| labels | shared lowercase ASCII segment grammar (`-._/:` separators), nonempty and at most 128 bytes; mutable-ref exclusion only where AG applies it | semantic intake |
| times and other JSON integers | exact safe range `[-9007199254740991,9007199254740991]` | before canonical identity/persistence |

Absent optional checkpoint members are omitted; explicit `null` refuses.  A
present work checkpoint always carries its content-manifest identity.

Before unknown-outcome reconciliation invokes an executor reconciliation
operation or advances custody, Docket freshly verifies the exact stored
starting checkpoint.  Reconciliation never repeats ordinary execution.  The
durable attempt journal is the cumulative ordered sequence across indeterminate
and terminal observations; a later empty or partial response cannot erase an
earlier effect.  Exact duplicate entries follow the declared idempotency law,
while conflicting entries refuse. The known-settlement artifact binds the
final cumulative-journal identity. Its identity covers the complete canonical
settlement body other than the identity field itself, including settlement
time; changed time or journal bytes under the old identity refuse on durable
read and replay. Terminal construction appends the executor observation,
re-reads the validated cumulative identity, and writes the settlement in one
immediate Store transaction.

The ordinary executor path reports and Docket validates journal membership.
Its truthful claim is `no_unauthorized_effect_reported`, not physical proof
that an unmediated executor performed no other effect.  Executor completeness,
physical containment, and physical idempotency remain operational premises.
The companion `reported_authorized_effects_occurred` flag is derived only from
the cumulative reported journal. Migration either proves that a historical
terminal journal already includes every earlier ordinary observation or fails
atomically; it never silently rewrites a sealed identity chain.
Rejected R1 governed-repair terminal rows remain stored historical bytes after
migration, but because R1 omitted the truthful observation from its requirement
identity they cannot replay as current R2 governed results. Rejected-R1 ordinary
settlement rows are validated and retained in dedicated immutable legacy
identity/canonical-wire columns before the active journal-bound projection is
derived. An incomplete legacy terminal refuses and rolls the additive migration
back.

Requested-delta identities and all nested durable variants are revalidated on
read and replay.  Exact bytes replay idempotently; identity reuse with changed
bytes fails closed.  Docket neither approves scope expansion nor interprets NQ
diagnostic meaning.

## Nonclaims

This correction is not qualification, independent review, a controlled NQ
fixture campaign, certificate issuance, deployment, activation, physical
containment, or global external-receipt coordination.  Operational
qualification remains `not_assessed`.
