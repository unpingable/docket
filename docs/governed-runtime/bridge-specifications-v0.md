# Bridge Specifications v0

A bridge is a named, versioned, exact crossing from one domain judgment to another: fixed
input type, fixed output type, declared information transported, declared information not
transported, declared precision lost, required authority, output receipt, typed refusals.

Exactly four bridges exist. **An absent bridge means no judgment transfer** — where no
bridge is declared, the correct output is a first-class reliance refusal, never a default,
fallback, or pass-through (invariant 30, proved negative N3). There is no generic policy
evaluator, no dynamic bridge registry, no blanket conversion, no universal judgment type
(N1, N2), and no blanket `From` implementations.

Version behavior is identical for all four: only the named `V1` input is accepted. Any
other version — older, newer, or unknown — produces the typed refusal
`BridgeVersionUnsupported`. No fallback path exists.

---

## StandingToRatificationV1

- **Source judgment:** a standing token is mechanically valid — integrity-intact, scoped
  to this actor, this act (ratify), this exact prepared-attempt digest and repository,
  unexpired at the runtime clock reading, unconsumed.
- **Target judgment:** this actor is ratified onto this exact prepared attempt, by digest.
- **Information transported:** actor identity; the exact scope binding
  (attempt digest, repository); expiry validity at a named clock reading; the fact of
  one-use consumption.
- **Information explicitly not transported:** why the standing was granted; whether the
  grant was institutionally justified; anything about the candidate's correctness, safety,
  or completeness; approval of the idea (ratification is commitment to an exact artifact,
  not approval of a thing).
- **Precision lost:** the grant's institutional origin and history are reduced to the
  token's mechanical validity; nothing of the grantor's intent survives the crossing.
- **Required authority:** the standing token itself, verified by the runtime; the runtime
  clock. Nothing a labor provider holds is standing.
- **Output receipt:** `RatificationReceipt { attempt_id, prepared_attempt_digest, actor,
  standing_use_id, clock_reading }`.
- **Typed refusals:** `StandingIntegrityFailure`, `StandingScopeMismatch`,
  `StandingExpired`, `StandingAlreadyUsed`, `RatificationDigestMismatch`,
  `RatificationBasisMismatch`, `BridgeVersionUnsupported`.
- **Consumption:** success consumes the standing use exactly once. Every refusal above
  consumes nothing.

## ReservationToDispatchV1

- **Source judgment:** an exclusive one-use reservation is held for exactly this tuple —
  repository, target ref, basis, attempt — unexpired and unconsumed, and a ratification
  receipt exists for the same attempt.
- **Target judgment:** exactly one dispatch may be minted for this attempt, identified by
  the one `DispatchId`.
- **Information transported:** the exclusivity fact; the exact reservation tuple; expiry
  validity; consumption of the single use; the ratification linkage.
- **Information explicitly not transported:** any prediction that the dispatch will
  succeed; anything about candidate correctness; the wisdom of ratifying; queue position
  or contention history (conflict produced refusal, not waiting).
- **Precision lost:** the reservation's contention history is not carried; only the held
  claim crosses.
- **Required authority:** the reservation handle and the persisted ratification receipt.
  Providers never hold reservation handles.
- **Output receipt:** `DispatchEnvelope { dispatch_id, attempt_id, prepared_attempt_digest,
  reservation_use_id, repository, target_ref, expected_basis }` — persisted before the
  broker sees it.
- **Typed refusals:** `ReservationExpired`, `ReservationAlreadyUsed`,
  `ReservationAttemptMismatch`, `ReservationConflict`, `RatificationMissing`,
  `DispatchIdentityConflict` (a second `DispatchId` for the same attempt),
  `BridgeVersionUnsupported`.
- **Consumption:** success consumes the reservation use exactly once; refusals consume
  nothing.

## ObservationToReviewQueueV1

- **Source judgment:** an observation record establishes that a named command, with exact
  argv, exited zero against an exactly named result commit produced by an admitted,
  committed effect.
- **Target judgment (the only admissible claim):**

  > This exact result commit was produced by the admitted effect, and the named command
  > exited successfully against it.

- **Information transported:** the exact command identity (argv, working-directory
  identity, environment description); the exit status; the result-commit binding; the
  linkage to the committed effect.
- **Information explicitly not transported — refused claims:** the patch is correct; the
  task is complete; the result is safe to merge; the obligation is discharged; the work
  may be closed. Observation is not proof of anything but itself (invariant 19).
- **Precision lost:** command output is reduced to digests and exit status; the
  environment is reduced to its recorded description; nothing about *why* the command
  passed crosses.
- **Required authority:** none beyond the observation record and the commitment record —
  this is a consumer-side admission whose consumer is the human-review queue. Reliance is
  consumer-indexed and claim-indexed; it is not a pure function of the receipt (N4), and a
  reliance decision returning one boolean has already lost.
- **Output receipt:** `ReviewQueueAdmission { attempt_id, result_commit, admitted_claim }`.
- **Typed refusals:** `ObservationFailed` (non-zero exit admits nothing),
  `ObservationScopeMismatch` (an observation of commit A supports no claim about commit
  B), `ObservationOutOfScope` (consumer or claim outside this bridge),
  `ClaimNotAdmissible` (any of the five refused claims), `BridgeVersionUnsupported`.
- **Consumption:** none — observations are records, not resources. Admission does not
  mutate the observation; refusal does not mutate it either (invariant 22).

## RecoveryStandingToResolutionV1

- **Source judgment:** *both* of — (a) an authentic recovery fact whose bindings exactly
  match this attempt and this dispatch (attempt, dispatch, effect, prepared-attempt
  digest, repository, target ref, basis, observed ref, expected result commit where
  available, broker journal digest, fact source); and (b) recovery standing held by the
  resolving actor — separate authority, distinct from and not implied by the standing that
  ratified the attempt. Either alone is refused: authenticity is not authority.
- **Target judgment:** the indeterminate attempt is resolved to exactly one of
  `CommittedViaRecovery` or `ProvenNotCommitted`.
- **Information transported:** the fact's exact bindings; the identity of the resolving
  actor; consumption of the recovery-standing use; which of the two resolutions the
  evidence establishes.
- **Information explicitly not transported:** fault or blame; correctness of the
  candidate; whether retrying (as a new attempt) is wise; any reclassification of
  `DispatchRefused` (invariant 28); obligation discharge.
- **Precision lost:** the resolution records what the evidence established, not the full
  worldstate at recovery time; conflicting evidence is not weighed — conflict produces no
  resolution and the attempt remains `Indeterminate`.
- **Required authority:** the recovery standing token, one-use, integrity-verified.
- **Output receipt:** `RecoveryResolutionReceipt { attempt_id, dispatch_id, resolution,
  recovery_fact_id, recovery_standing_use_id, clock_reading }`.
- **Typed refusals:** `RecoveryAttemptMismatch`, `RecoveryDispatchMismatch`,
  `RecoveryBindingIncomplete`, `RecoveryStandingInsufficient`, `RecoveryStandingExpired`,
  `RecoveryStandingAlreadyUsed`, `ConflictingRecoveryEvidence` (state remains
  `Indeterminate`), `BridgeVersionUnsupported`.
- **Consumption:** successful resolution consumes the recovery-standing use once.
  Mismatched facts and insufficient standing consume nothing and leave state unchanged.

---

## What no bridge does

No bridge transports correctness, merge safety, completion, or obligation discharge. No
bridge output feeds another bridge's input implicitly. No bridge exists from any refusal
to its negation (N5): "this attempt returned `NoStanding`" is established; "the subject
lacked standing" is not.
