# NQ C1 repair-boundary conformance vectors

These are byte-identical copies of AG's immutable NQ C1 historical specimens.
They are inputs to Docket conformance tests, not Docket persistence records and
not evidence that Docket governed the historical events.

The records exercise four mutually exclusive facts:

- exact independently rejected candidate and evidence packet;
- a 28-path census stopped before spend when path 29 was discovered;
- a distinct 29-path occurrence consumed once, checkpointed, then stopped at
  a newly discovered manifest-schema path; and
- architectural readjudication required for the reported 32/945/33 census,
  rather than laundering 23 additional diagnostic files into bounded repair.

`DIGESTS.txt` pins exact LF-terminated file bytes. The AG semantic digest is an
opaque upstream identity to Docket. Docket derives its own identities from
explicit versioned transcripts; it never recomputes AG's JCS digest.

Every vector says `authority_use: historical_evidence_only`. Possession,
parsing, or replay of a vector mints no campaign-stage standing, burn,
reservation, receipt, repair authority, qualification, or certificate.

The former campaign-stage `exact_repair`, `records_repair_stage`, and
`existing_source_scope_repair_stage` vocabulary is retained only so these
archives and persisted historical rows remain intelligible. Current public
constructors, Store mutation adapters, runtime services, and CLI verbs refuse
that route. Any new repair occurrence must enter the distinct governed-repair
custody protocol; these fixtures are not a bootstrap premise for it.
