# Provenance

This repository contains the greenfield governed work runtime frozen as
`gwr-greenfield-v0.1`.

This project is human-directed and AI-assisted. Final design authority, acceptance
criteria, and editorial control rest with the human author. AI contributions were
material and are categorized below by function.

## Design ancestry

The runtime design derives from the governed admissibility, transport, settlement, and
recovery work developed in the associated Lean research corpus, particularly the v14 and
v15 lines.

Much of that formal work was developed interactively with Codex using Sol, under
direction and review by James Beck. Where an invariant in this repository is tagged
`proved`, the proof is external to this repository and is cited by name in
`docs/governed-runtime/invariants-v0.md`; it is not reproduced or re-derived here.

## Implementation

The initial greenfield Rust implementation was produced primarily by Fable (Anthropic)
via Claude Code, from the corrected greenfield plan and normative packet.

The implementation was intentionally developed without adapting the prior Rust runtime.
The build sessions ran under an isolation rule restricting readable paths to the
workspace and the normative packet, because a comparison against prior implementations
is a separate, still-unperformed deliverable. Comparison and repair follow the
greenfield build rather than informing it.

## Review and repair

Codex and Claude performed independent conformance and adversarial reviews at different
stages. Material findings were reproduced with executable witnesses before repair, and
the witnesses were re-run against the patched tree.

The final pre-freeze campaign repaired path authorization, recovery binding, dispatch
re-entry, persistence encoding, token canonicalization, store transition validation, and
sealed authority values. A second blind review then re-ran the full invariant table and
every recorded witness, and closed three further findings: an unstated custody premise
underlying `ProvenNotCommitted`, non-canonical standing-token encodings, and an
unguarded empty observation plan.

The audit history is retained rather than rewritten. `docs/governed-runtime/conformance-v0.md`
remains marked superseded-in-part with its original classifications intact, and
`docs/governed-runtime/open-defects.md` retains the defects and the repair record.

## Authority

AI systems contributed design analysis, implementation, testing, and review. They did not
independently authorize scope, trust assumptions, invariant claims, release boundaries, or
the freeze. Those decisions were made and accepted by the repository maintainer.

See `docs/governed-runtime/greenfield-result.md` and
`docs/governed-runtime/trust-model.md` for the precise claims and assumptions of
`gwr-greenfield-v0.1`.

## Provenance basis and limits

This document is a functional attribution record based on commit history, co-author
trailers (where present), project notes, and documented working sessions. It is not a
complete forensic account of all contributions.

Some AI contributions — especially design critique, rejected alternatives, and footguns
avoided — may not appear in repository artifacts or commit metadata.

Model names and tools are recorded at the platform level; exact model versions may vary
across sessions and are not exhaustively reconstructed here.

## What this document does not claim

- No exact proportional attribution. Contributions are categorized by function, not
  quantified by token count or lines of code.
- Design and implementation were not cleanly sequential. Architecture informed code, code
  revealed design gaps, and the feedback loop was continuous.
- "Footguns avoided" and "ideas that didn't ship" are real contributions that leave no
  artifact. This document cannot fully account for them.

---

This document reflects the project state as of 2026-07-25 and may be revised.
