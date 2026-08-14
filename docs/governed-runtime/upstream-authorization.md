# Retired upstream authorization V1

`ag.docket-issuance:v1` is historical evidence only. R3 removes its public
intake, its trust-file verifier, the `docket authz accept` command, and the
service and Store write operations that formerly minted standing from it.

`docket authz request` remains a non-authorizing projection of a prepared
attempt. Exporting that testimony grants no standing and there is no current
production consumer that can turn a V1 response into consequence.

Existing database rows remain readable by dossier and audit views. They retain
their original `upstream` source label and exact bytes so historical operation
can be interpreted. Reopening or displaying such a row cannot create a new
grant, custody, attempt, execution, or successor. An unconsumed historical
`upstream` grant is consequence-inert: the transactional standing-consumption
boundary returns `LegacyUpstreamIssuanceRetired` without consuming it or
advancing an attempt.

The only current repair-custody intake is `governed-loop accept`, which consumes
the exact AG governed-loop V2 issuance under the canonical Store-owned path.
