//! SQLite custody for terminal governed-repair requirements.
//!
//! Executor output is evidence.  Only this Docket-owned boundary validates it
//! against the exact accepted issuance and custody, appends an immutable
//! checkpoint, and derives the sealed result AG may consume.  The result is a
//! terminal outcome for the existing attempt; it is not repair standing.

use crate::governed_loop::{
    AgIssuanceWireV2, CanonicalEffectOperationWireV1, CanonicalEffectScopeWireV1,
    DocketCustodyWireV1,
};
use gwr_core::digest::{Sha256Digest, Transcript};
use gwr_core::governed_repair::{
    BlockedEffectV1, CanonicalEffectOperationV1, CanonicalEffectScopeV1, EffectResourceV1,
    GovernedRepairBindingV1, GovernedRepairRequirementV1, ReadjudicationRequiredV1,
    ScopeExpansionRequiredV1,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

pub const SCOPE_EXPANSION_REQUIRED_SCHEMA_V1: &str =
    "docket.governed-repair.scope-expansion-required/v1";
pub const READJUDICATION_REQUIRED_SCHEMA_V1: &str =
    "docket.governed-repair.readjudication-required/v1";
pub const GOVERNED_REPAIR_CHECKPOINT_SCHEMA_V1: &str = "docket.governed-repair.checkpoint/v1";
pub const SEALED_GOVERNED_REPAIR_RESULT_SCHEMA_V1: &str = "docket.governed-repair.sealed-result/v1";

pub type RequestedEffectDeltaWireV1 = CanonicalEffectScopeWireV1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockedEffectWireV1 {
    pub effect_class: String,
    pub resource: String,
    pub path: String,
    pub operation: CanonicalEffectOperationWireV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "requirement", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutorGovernedRepairRequirementWireV1 {
    ScopeExpansionRequired {
        requested_delta: RequestedEffectDeltaWireV1,
        requested_delta_digest: String,
        blocked_effect: BlockedEffectWireV1,
        reason: String,
        dependency_evidence: Vec<String>,
        created_at_unix_ms: u64,
        expires_at_unix_ms: u64,
        idempotency: String,
        limitations: Vec<String>,
    },
    ReadjudicationRequired {
        question: String,
        evidence_census: Vec<String>,
        diagnostic_census: Vec<String>,
        bounded_alternatives: Vec<String>,
        unresolved_facts: Vec<String>,
        adjudication_scope: CanonicalEffectScopeWireV1,
        created_at_unix_ms: u64,
        expires_at_unix_ms: u64,
        idempotency: String,
        limitations: Vec<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedRepairBindingWireV1 {
    pub campaign: String,
    pub occurrence: String,
    pub proposal: String,
    pub observation: String,
    pub standing_resolution: String,
    pub admission_decision: String,
    pub spend: String,
    pub issuance: String,
    pub custody: String,
    pub attempt: String,
    pub executor_result: String,
    pub executor_binding: String,
    pub original_scope: CanonicalEffectScopeWireV1,
    pub original_scope_digest: String,
    pub effect_journal_digest: String,
    pub reported_authorized_effects_occurred: bool,
    pub created_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub idempotency: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeExpansionRequiredWireV1 {
    pub schema: String,
    pub requirement_identity: String,
    pub binding: GovernedRepairBindingWireV1,
    pub requested_delta: RequestedEffectDeltaWireV1,
    pub requested_delta_digest: String,
    pub blocked_effect: BlockedEffectWireV1,
    pub reason: String,
    pub dependency_evidence: Vec<String>,
    /// True only when the complete journal reported by the mediated executor
    /// contains no effect outside issuance scope. It is not a claim of
    /// physical non-occurrence beyond that reporting boundary.
    pub no_unauthorized_effect_reported: bool,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadjudicationRequiredWireV1 {
    pub schema: String,
    pub requirement_identity: String,
    pub binding: GovernedRepairBindingWireV1,
    pub question: String,
    pub evidence_census: Vec<String>,
    pub diagnostic_census: Vec<String>,
    pub bounded_alternatives: Vec<String>,
    pub unresolved_facts: Vec<String>,
    pub adjudication_scope: CanonicalEffectScopeWireV1,
    /// True only when the complete journal reported by the mediated executor
    /// contains no effect outside issuance scope. It is not a claim of
    /// physical non-occurrence beyond that reporting boundary.
    pub no_unauthorized_effect_reported: bool,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "requirement",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum SealedGovernedRepairRequirementWireV1 {
    ScopeExpansionRequired(ScopeExpansionRequiredWireV1),
    ReadjudicationRequired(ReadjudicationRequiredWireV1),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedRepairCheckpointWireV1 {
    pub schema: String,
    pub checkpoint: String,
    pub issuance: String,
    pub custody: String,
    pub attempt: String,
    pub executor_binding: String,
    pub executor_result: String,
    pub executor_receipt: String,
    pub requirement_kind: String,
    pub requirement_identity: String,
    pub effect_journal_digest: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::governed_loop::deserialize_present_some"
    )]
    pub immutable_work_checkpoint: Option<ImmutableWorkCheckpointWireV1>,
    pub idempotency: String,
    pub created_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImmutableWorkCheckpointWireV1 {
    pub repository_identity: String,
    pub commit: String,
    pub tree: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::governed_loop::deserialize_present_some"
    )]
    pub diff_identity: Option<String>,
    pub content_manifest_identity: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectJournalEntryWireV1 {
    pub resource: String,
    pub path: String,
    pub operation: CanonicalEffectOperationWireV1,
    pub effect_identity: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreSealedGovernedRepairResultV1 {
    pub schema: String,
    pub sealed_result: String,
    pub checkpoint: GovernedRepairCheckpointWireV1,
    pub outcome: SealedGovernedRepairRequirementWireV1,
}

pub(crate) struct SealRequirementInputV1<'a> {
    pub issuance: &'a AgIssuanceWireV2,
    pub custody: &'a DocketCustodyWireV1,
    pub executor_binding: &'a str,
    pub executor_receipt: &'a str,
    pub draft: ExecutorGovernedRepairRequirementWireV1,
    pub journal: &'a [EffectJournalEntryWireV1],
    pub immutable_work_checkpoint: Option<&'a ImmutableWorkCheckpointWireV1>,
    pub now_unix_ms: u64,
}

pub(crate) fn seal_requirement(
    connection: &mut Connection,
    input: SealRequirementInputV1<'_>,
) -> Result<StoreSealedGovernedRepairResultV1, String> {
    let SealRequirementInputV1 {
        issuance,
        custody,
        executor_binding,
        executor_receipt,
        draft,
        journal: latest_journal,
        immutable_work_checkpoint,
        now_unix_ms,
    } = input;
    parse_digest(executor_receipt)?;
    // An immediate transaction makes the cumulative-journal read, terminal
    // checkpoint insert, and custody terminalization one indivisible Store
    // decision. A late indeterminate observation can neither disappear from
    // the seal nor append after it.
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| format!("governed-repair-transaction:{error}"))?;
    let journal =
        cumulative_effect_journal_with(&tx, &issuance.issuance, &custody.attempt, latest_journal)?;
    let executor_result = executor_result_identity(
        executor_receipt,
        &draft,
        &journal,
        immutable_work_checkpoint,
    )?;
    let effect_journal_digest = validate_effect_journal(&issuance.effect_scope, &journal)?;
    if let ExecutorGovernedRepairRequirementWireV1::ScopeExpansionRequired {
        blocked_effect, ..
    } = &draft
    {
        if journal.iter().any(|entry| {
            entry.resource == blocked_effect.resource
                && entry.path == blocked_effect.path
                && entry.operation == blocked_effect.operation
        }) {
            return Err("governed-repair-blocked-effect-was-performed".to_owned());
        }
    }
    if let Some(checkpoint) = immutable_work_checkpoint {
        validate_work_checkpoint(checkpoint)?;
    }
    // This is the upstream AG custody reference carried back across the wire,
    // not a Docket-native checkpoint identity.  Preserve AG's exact JCS/domain
    // law so AG can join the sealed result to the custody it issued.
    let custody_identity = ag_custody_reference(custody)?;
    let common = common_binding(CommonBindingInputV1 {
        issuance,
        custody,
        custody_identity: &custody_identity,
        executor_binding,
        executor_result: &executor_result,
        effect_journal_digest: &effect_journal_digest,
        reported_authorized_effects_occurred: !journal.is_empty(),
        draft: &draft,
    })?;
    validate_ag_effect_scope_identity(&issuance.effect_scope, &issuance.effect_scope_digest)?;
    let (requirement, wire) = convert_requirement(common, draft)?;
    let requirement_identity = qualified(
        requirement
            .validate(now_unix_ms)
            .map_err(|refusal| format!("governed-repair-refused:{refusal:?}"))?,
    );
    let kind = requirement.kind();
    let outcome = wire.with_identity(requirement_identity.clone());
    let checkpoint_identity = checkpoint_identity(
        &issuance.issuance,
        &custody_identity,
        &custody.attempt,
        executor_binding,
        &executor_result,
        executor_receipt,
        kind,
        &requirement_identity,
        &qualified(requirement.binding().effect_journal_digest),
        immutable_work_checkpoint,
        &qualified(requirement.binding().idempotency),
        requirement.binding().created_at_unix_ms,
        requirement.binding().expires_at_unix_ms,
    );
    let checkpoint = GovernedRepairCheckpointWireV1 {
        schema: GOVERNED_REPAIR_CHECKPOINT_SCHEMA_V1.to_owned(),
        checkpoint: checkpoint_identity,
        issuance: issuance.issuance.clone(),
        custody: custody_identity,
        attempt: custody.attempt.clone(),
        executor_binding: executor_binding.to_owned(),
        executor_result: executor_result.to_owned(),
        executor_receipt: executor_receipt.to_owned(),
        requirement_kind: kind.to_owned(),
        requirement_identity,
        effect_journal_digest: qualified(requirement.binding().effect_journal_digest),
        immutable_work_checkpoint: immutable_work_checkpoint.cloned(),
        idempotency: qualified(requirement.binding().idempotency),
        created_at_unix_ms: requirement.binding().created_at_unix_ms,
        expires_at_unix_ms: requirement.binding().expires_at_unix_ms,
    };
    let sealed_result = sealed_result_identity(&checkpoint);
    let result = StoreSealedGovernedRepairResultV1 {
        schema: SEALED_GOVERNED_REPAIR_RESULT_SCHEMA_V1.to_owned(),
        sealed_result,
        checkpoint,
        outcome,
    };
    append_exact(&tx, issuance, &result, &journal)?;
    tx.commit()
        .map_err(|error| format!("governed-repair-commit:{error}"))?;
    read_sealed_result(connection, &issuance.issuance)?
        .ok_or_else(|| "governed-repair-checkpoint-disappeared".to_owned())
}

pub(crate) fn read_sealed_result(
    connection: &Connection,
    issuance: &str,
) -> Result<Option<StoreSealedGovernedRepairResultV1>, String> {
    let common = connection
        .query_row(
            "SELECT checkpoint,sealed_result,custody,attempt,executor_binding,executor_result,executor_receipt,
                    requirement_kind,requirement_identity,campaign,occurrence,proposal,observation,
                    standing_resolution,admission_decision,spend,original_scope_digest,
                    effect_journal_digest,effect_journal_entries,work_repository_identity,work_commit,work_tree,
                    work_diff_identity,work_content_manifest_identity,reported_authorized_effects_occurred,
                    idempotency,created_at,expires_at
             FROM governed_repair_checkpoint WHERE issuance=?1",
            [issuance],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, String>(14)?,
                    row.get::<_, String>(15)?,
                    row.get::<_, String>(16)?,
                    row.get::<_, String>(17)?,
                    row.get::<_, String>(18)?,
                    row.get::<_, Option<String>>(19)?,
                    row.get::<_, Option<String>>(20)?,
                    row.get::<_, Option<String>>(21)?,
                    row.get::<_, Option<String>>(22)?,
                    row.get::<_, Option<String>>(23)?,
                    row.get::<_, i64>(24)?,
                    row.get::<_, String>(25)?,
                    row.get::<_, i64>(26)?,
                    row.get::<_, i64>(27)?,
                ))
            },
        )
        .optional()
        .map_err(|error| format!("governed-repair-read:{error}"))?;
    let Some((
        checkpoint,
        sealed_result,
        custody,
        attempt,
        executor_binding,
        executor_result,
        executor_receipt,
        kind,
        requirement_identity,
        campaign,
        occurrence,
        proposal,
        observation,
        standing_resolution,
        admission_decision,
        spend,
        original_scope_digest,
        effect_journal_digest,
        effect_journal_entries,
        work_repository,
        work_commit,
        work_tree,
        work_diff,
        work_manifest,
        reported_authorized_effects_occurred,
        idempotency,
        created_at,
        expires_at,
    )) = common
    else {
        return Ok(None);
    };
    let no_unauthorized_effect_reported: i64 = connection
        .query_row(
            "SELECT no_unauthorized_effect_reported
             FROM governed_repair_checkpoint WHERE issuance=?1",
            [issuance],
            |row| row.get(0),
        )
        .map_err(|error| format!("governed-repair-observation-read:{error}"))?;
    if no_unauthorized_effect_reported != 1 {
        return Err("governed-repair-observation-substitution".to_owned());
    }
    let signed_body: String = connection
        .query_row(
            "SELECT signed_body_b64 FROM governed_loop_attempt WHERE issuance=?1",
            [issuance],
            |row| row.get(0),
        )
        .map_err(|error| format!("governed-repair-issuance-read:{error}"))?;
    let issuance_body = decode_base64url(&signed_body)?;
    let issuance_wire: AgIssuanceWireV2 =
        crate::governed_loop::strict_json(&issuance_body, "governed-repair-issuance")?;
    let binding = GovernedRepairBindingWireV1 {
        campaign,
        occurrence,
        proposal,
        observation,
        standing_resolution,
        admission_decision,
        spend,
        issuance: issuance.to_owned(),
        custody: custody.clone(),
        attempt: attempt.clone(),
        executor_result: executor_result.clone(),
        executor_binding: executor_binding.clone(),
        original_scope: issuance_wire.effect_scope.clone(),
        original_scope_digest,
        effect_journal_digest: effect_journal_digest.clone(),
        reported_authorized_effects_occurred: reported_authorized_effects_occurred == 1,
        created_at_unix_ms: to_u64(created_at)?,
        expires_at_unix_ms: to_u64(expires_at)?,
        idempotency: idempotency.clone(),
    };
    let outcome = match kind.as_str() {
        "scope_expansion_required" => {
            read_scope(connection, &checkpoint, binding, &requirement_identity)?
        }
        "readjudication_required" => {
            read_readjudication(connection, &checkpoint, binding, &requirement_identity)?
        }
        _ => return Err("governed-repair-kind-corrupt".to_owned()),
    };
    let checkpoint_wire = GovernedRepairCheckpointWireV1 {
        schema: GOVERNED_REPAIR_CHECKPOINT_SCHEMA_V1.to_owned(),
        checkpoint,
        issuance: issuance.to_owned(),
        custody,
        attempt,
        executor_binding,
        executor_result,
        executor_receipt,
        requirement_kind: kind,
        requirement_identity,
        effect_journal_digest,
        immutable_work_checkpoint: match (
            work_repository,
            work_commit,
            work_tree,
            work_diff,
            work_manifest,
        ) {
            (None, None, None, None, None) => None,
            (
                Some(repository_identity),
                Some(commit),
                Some(tree),
                diff_identity,
                Some(content_manifest_identity),
            ) => Some(ImmutableWorkCheckpointWireV1 {
                repository_identity,
                commit,
                tree,
                diff_identity,
                content_manifest_identity,
            }),
            _ => return Err("governed-repair-work-checkpoint-corrupt".to_owned()),
        },
        idempotency,
        created_at_unix_ms: to_u64(created_at)?,
        expires_at_unix_ms: to_u64(expires_at)?,
    };
    let result = StoreSealedGovernedRepairResultV1 {
        schema: SEALED_GOVERNED_REPAIR_RESULT_SCHEMA_V1.to_owned(),
        sealed_result,
        checkpoint: checkpoint_wire,
        outcome,
    };
    validate_read_result(
        &result,
        &issuance_wire,
        &decode_journal(&effect_journal_entries)?,
    )?;
    Ok(Some(result))
}

enum OutcomeWithoutIdentity {
    Scope(ScopeExpansionRequiredWireV1),
    Readjudication(ReadjudicationRequiredWireV1),
}

impl OutcomeWithoutIdentity {
    fn with_identity(mut self, identity: String) -> SealedGovernedRepairRequirementWireV1 {
        match &mut self {
            Self::Scope(value) => value.requirement_identity = identity,
            Self::Readjudication(value) => value.requirement_identity = identity,
        }
        match self {
            Self::Scope(value) => {
                SealedGovernedRepairRequirementWireV1::ScopeExpansionRequired(value)
            }
            Self::Readjudication(value) => {
                SealedGovernedRepairRequirementWireV1::ReadjudicationRequired(value)
            }
        }
    }
}

struct CommonBindingInputV1<'a> {
    issuance: &'a AgIssuanceWireV2,
    custody: &'a DocketCustodyWireV1,
    custody_identity: &'a str,
    executor_binding: &'a str,
    executor_result: &'a str,
    effect_journal_digest: &'a str,
    reported_authorized_effects_occurred: bool,
    draft: &'a ExecutorGovernedRepairRequirementWireV1,
}

fn common_binding(input: CommonBindingInputV1<'_>) -> Result<GovernedRepairBindingWireV1, String> {
    let CommonBindingInputV1 {
        issuance,
        custody,
        custody_identity,
        executor_binding,
        executor_result,
        effect_journal_digest,
        reported_authorized_effects_occurred,
        draft,
    } = input;
    for value in [executor_binding, executor_result, custody_identity] {
        parse_digest(value)?;
    }
    let (created, expires, idempotency) = match draft {
        ExecutorGovernedRepairRequirementWireV1::ScopeExpansionRequired {
            created_at_unix_ms,
            expires_at_unix_ms,
            idempotency,
            ..
        }
        | ExecutorGovernedRepairRequirementWireV1::ReadjudicationRequired {
            created_at_unix_ms,
            expires_at_unix_ms,
            idempotency,
            ..
        } => (*created_at_unix_ms, *expires_at_unix_ms, idempotency),
    };
    parse_digest(effect_journal_digest)?;
    parse_digest(idempotency)?;
    Ok(GovernedRepairBindingWireV1 {
        campaign: issuance.key.campaign.clone(),
        occurrence: issuance.key.occurrence.clone(),
        proposal: issuance.proposal.clone(),
        observation: issuance.observation.clone(),
        standing_resolution: issuance.standing_resolution.clone(),
        admission_decision: issuance.admission_decision.decision.clone(),
        spend: issuance.spend.clone(),
        issuance: issuance.issuance.clone(),
        custody: custody_identity.to_owned(),
        attempt: custody.attempt.clone(),
        executor_result: executor_result.to_owned(),
        executor_binding: executor_binding.to_owned(),
        original_scope: issuance.effect_scope.clone(),
        original_scope_digest: issuance.effect_scope_digest.clone(),
        effect_journal_digest: effect_journal_digest.to_owned(),
        reported_authorized_effects_occurred,
        created_at_unix_ms: created,
        expires_at_unix_ms: expires,
        idempotency: idempotency.clone(),
    })
}

fn convert_requirement(
    binding: GovernedRepairBindingWireV1,
    draft: ExecutorGovernedRepairRequirementWireV1,
) -> Result<(GovernedRepairRequirementV1, OutcomeWithoutIdentity), String> {
    let core_binding = to_core_binding(&binding)?;
    Ok(match draft {
        ExecutorGovernedRepairRequirementWireV1::ScopeExpansionRequired {
            requested_delta,
            requested_delta_digest,
            blocked_effect,
            reason,
            dependency_evidence,
            limitations,
            ..
        } => {
            validate_ag_effect_scope_identity(&requested_delta, &requested_delta_digest)?;
            let core_delta = to_core_delta(&requested_delta);
            let core = ScopeExpansionRequiredV1 {
                binding: core_binding,
                requested_delta: core_delta,
                requested_delta_digest: parse_digest(&requested_delta_digest)?,
                blocked_effect: BlockedEffectV1 {
                    effect_class: blocked_effect.effect_class.clone(),
                    resource: blocked_effect.resource.clone(),
                    path: blocked_effect.path.clone(),
                    operation: to_core_operation(blocked_effect.operation),
                },
                reason: parse_digest(&reason)?,
                dependency_evidence: parse_digests(&dependency_evidence)?,
                no_unauthorized_effect_reported: true,
                limitations: parse_digests(&limitations)?,
            };
            let wire = ScopeExpansionRequiredWireV1 {
                schema: SCOPE_EXPANSION_REQUIRED_SCHEMA_V1.to_owned(),
                requirement_identity: String::new(),
                binding,
                requested_delta,
                requested_delta_digest,
                blocked_effect,
                reason,
                dependency_evidence,
                no_unauthorized_effect_reported: true,
                limitations,
            };
            (
                GovernedRepairRequirementV1::ScopeExpansion(core),
                OutcomeWithoutIdentity::Scope(wire),
            )
        }
        ExecutorGovernedRepairRequirementWireV1::ReadjudicationRequired {
            question,
            evidence_census,
            diagnostic_census,
            bounded_alternatives,
            unresolved_facts,
            adjudication_scope,
            limitations,
            ..
        } => {
            let core = ReadjudicationRequiredV1 {
                binding: core_binding,
                question: parse_digest(&question)?,
                evidence_census: parse_digests(&evidence_census)?,
                diagnostic_census: parse_digests(&diagnostic_census)?,
                bounded_alternatives: parse_digests(&bounded_alternatives)?,
                unresolved_facts: parse_digests(&unresolved_facts)?,
                adjudication_scope: to_core_scope(&adjudication_scope),
                no_unauthorized_effect_reported: true,
                limitations: parse_digests(&limitations)?,
            };
            let wire = ReadjudicationRequiredWireV1 {
                schema: READJUDICATION_REQUIRED_SCHEMA_V1.to_owned(),
                requirement_identity: String::new(),
                binding,
                question,
                evidence_census,
                diagnostic_census,
                bounded_alternatives,
                unresolved_facts,
                adjudication_scope,
                no_unauthorized_effect_reported: true,
                limitations,
            };
            (
                GovernedRepairRequirementV1::Readjudication(core),
                OutcomeWithoutIdentity::Readjudication(wire),
            )
        }
    })
}

fn append_exact(
    tx: &Transaction<'_>,
    issuance: &AgIssuanceWireV2,
    result: &StoreSealedGovernedRepairResultV1,
    journal: &[EffectJournalEntryWireV1],
) -> Result<(), String> {
    if let Some(existing) = read_sealed_result(tx, &issuance.issuance)? {
        return if existing == *result {
            Ok(())
        } else {
            Err("governed-repair-exact-replay-collision".to_owned())
        };
    }
    let status: String = tx
        .query_row(
            "SELECT status FROM governed_loop_attempt WHERE issuance=?1 AND attempt=?2",
            params![issuance.issuance, result.checkpoint.attempt],
            |row| row.get(0),
        )
        .map_err(|error| format!("governed-repair-custody-missing:{error}"))?;
    if !matches!(status.as_str(), "accepted" | "indeterminate") {
        return Err("governed-repair-attempt-already-terminal".to_owned());
    }
    let binding = outcome_binding(&result.outcome);
    tx.execute(
        "INSERT INTO governed_repair_checkpoint
         (checkpoint,sealed_result,issuance,custody,attempt,executor_binding,executor_result,executor_receipt,
          requirement_kind,requirement_identity,campaign,occurrence,proposal,observation,
          standing_resolution,admission_decision,spend,original_scope_digest,effect_journal_digest,effect_journal_entries,
          work_repository_identity,work_commit,work_tree,work_diff_identity,work_content_manifest_identity,
          reported_authorized_effects_occurred,no_unauthorized_effect_reported,idempotency,created_at,expires_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,
                 ?19,?20,?21,?22,?23,?24,?25,?26,1,?27,?28,?29)",
        params![result.checkpoint.checkpoint, result.sealed_result, result.checkpoint.issuance,
            result.checkpoint.custody, result.checkpoint.attempt, result.checkpoint.executor_binding,
            result.checkpoint.executor_result, result.checkpoint.executor_receipt,
            result.checkpoint.requirement_kind,
            result.checkpoint.requirement_identity, binding.campaign, binding.occurrence,
            binding.proposal, binding.observation, binding.standing_resolution,
            binding.admission_decision, binding.spend, binding.original_scope_digest,
            binding.effect_journal_digest, encode_journal(journal),
            result.checkpoint.immutable_work_checkpoint.as_ref().map(|value| &value.repository_identity),
            result.checkpoint.immutable_work_checkpoint.as_ref().map(|value| &value.commit),
            result.checkpoint.immutable_work_checkpoint.as_ref().map(|value| &value.tree),
            result.checkpoint.immutable_work_checkpoint.as_ref().and_then(|value| value.diff_identity.as_ref()),
            result.checkpoint.immutable_work_checkpoint.as_ref().map(|value| &value.content_manifest_identity),
            i64::from(binding.reported_authorized_effects_occurred), binding.idempotency,
            to_i64(binding.created_at_unix_ms)?, to_i64(binding.expires_at_unix_ms)?],
    ).map_err(|error| format!("governed-repair-checkpoint-write:{error}"))?;
    match &result.outcome {
        SealedGovernedRepairRequirementWireV1::ScopeExpansionRequired(value) => {
            tx.execute(
                "INSERT INTO governed_repair_scope_expansion
                 (checkpoint,requested_delta_digest,requested_effect_class,requested_delta_resources,
                  blocked_effect_class,blocked_resource,blocked_path,blocked_operation,
                  reason,dependency_evidence,limitations)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                params![result.checkpoint.checkpoint, value.requested_delta_digest,
                    value.requested_delta.effect_class, encode_resources(&value.requested_delta.resources),
                    value.blocked_effect.effect_class, value.blocked_effect.resource,
                    value.blocked_effect.path, operation_tag(value.blocked_effect.operation),
                    value.reason, join_list(&value.dependency_evidence),
                    join_list(&value.limitations)],
            ).map_err(|error| format!("governed-repair-scope-write:{error}"))?;
        }
        SealedGovernedRepairRequirementWireV1::ReadjudicationRequired(value) => {
            tx.execute(
                "INSERT INTO governed_repair_readjudication
                 (checkpoint,question,evidence_census,diagnostic_census,bounded_alternatives,
                  unresolved_facts,adjudication_scope,limitations) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    result.checkpoint.checkpoint,
                    value.question,
                    join_list(&value.evidence_census),
                    join_list(&value.diagnostic_census),
                    join_list(&value.bounded_alternatives),
                    join_list(&value.unresolved_facts),
                    encode_scope(&value.adjudication_scope),
                    join_list(&value.limitations)
                ],
            )
            .map_err(|error| format!("governed-repair-readjudication-write:{error}"))?;
        }
    }
    Ok(())
}

fn outcome_binding(
    outcome: &SealedGovernedRepairRequirementWireV1,
) -> &GovernedRepairBindingWireV1 {
    match outcome {
        SealedGovernedRepairRequirementWireV1::ScopeExpansionRequired(value) => &value.binding,
        SealedGovernedRepairRequirementWireV1::ReadjudicationRequired(value) => &value.binding,
    }
}

fn to_core_binding(value: &GovernedRepairBindingWireV1) -> Result<GovernedRepairBindingV1, String> {
    Ok(GovernedRepairBindingV1 {
        campaign: parse_digest(&value.campaign)?,
        occurrence: value.occurrence.clone(),
        proposal: parse_digest(&value.proposal)?,
        observation: parse_digest(&value.observation)?,
        standing_resolution: parse_digest(&value.standing_resolution)?,
        decision: parse_digest(&value.admission_decision)?,
        spend: parse_digest(&value.spend)?,
        issuance: parse_digest(&value.issuance)?,
        custody: parse_digest(&value.custody)?,
        attempt: parse_digest(&value.attempt)?,
        executor_result: parse_digest(&value.executor_result)?,
        executor_binding: parse_digest(&value.executor_binding)?,
        original_scope: to_core_scope(&value.original_scope),
        original_scope_digest: parse_digest(&value.original_scope_digest)?,
        effect_journal_digest: parse_digest(&value.effect_journal_digest)?,
        reported_authorized_effects_occurred: value.reported_authorized_effects_occurred,
        created_at_unix_ms: value.created_at_unix_ms,
        expires_at_unix_ms: value.expires_at_unix_ms,
        idempotency: parse_digest(&value.idempotency)?,
    })
}

fn to_core_scope(value: &CanonicalEffectScopeWireV1) -> CanonicalEffectScopeV1 {
    CanonicalEffectScopeV1 {
        schema: value.schema.clone(),
        effect_class: value.effect_class.clone(),
        resources: value
            .resources
            .iter()
            .map(|resource| EffectResourceV1 {
                resource: resource.resource.clone(),
                path: resource.path.clone(),
                operations: resource
                    .operations
                    .iter()
                    .copied()
                    .map(to_core_operation)
                    .collect(),
            })
            .collect(),
    }
}

fn to_core_delta(value: &RequestedEffectDeltaWireV1) -> CanonicalEffectScopeV1 {
    to_core_scope(value)
}

const fn to_core_operation(value: CanonicalEffectOperationWireV1) -> CanonicalEffectOperationV1 {
    match value {
        CanonicalEffectOperationWireV1::Read => CanonicalEffectOperationV1::Read,
        CanonicalEffectOperationWireV1::Create => CanonicalEffectOperationV1::Create,
        CanonicalEffectOperationWireV1::Modify => CanonicalEffectOperationV1::Modify,
        CanonicalEffectOperationWireV1::Delete => CanonicalEffectOperationV1::Delete,
        CanonicalEffectOperationWireV1::Execute => CanonicalEffectOperationV1::Execute,
    }
}

const fn operation_tag(value: CanonicalEffectOperationWireV1) -> &'static str {
    match value {
        CanonicalEffectOperationWireV1::Read => "read",
        CanonicalEffectOperationWireV1::Create => "create",
        CanonicalEffectOperationWireV1::Modify => "modify",
        CanonicalEffectOperationWireV1::Delete => "delete",
        CanonicalEffectOperationWireV1::Execute => "execute",
    }
}

fn parse_operation(value: &str) -> Result<CanonicalEffectOperationWireV1, String> {
    match value {
        "read" => Ok(CanonicalEffectOperationWireV1::Read),
        "create" => Ok(CanonicalEffectOperationWireV1::Create),
        "modify" => Ok(CanonicalEffectOperationWireV1::Modify),
        "delete" => Ok(CanonicalEffectOperationWireV1::Delete),
        "execute" => Ok(CanonicalEffectOperationWireV1::Execute),
        _ => Err("governed-repair-operation-corrupt".to_owned()),
    }
}

fn read_scope(
    connection: &Connection,
    checkpoint: &str,
    binding: GovernedRepairBindingWireV1,
    identity: &str,
) -> Result<SealedGovernedRepairRequirementWireV1, String> {
    connection
        .query_row(
            "SELECT requested_delta_digest,requested_effect_class,requested_delta_resources,
        blocked_effect_class,blocked_resource,blocked_path,blocked_operation,
        reason,dependency_evidence,limitations
        FROM governed_repair_scope_expansion WHERE checkpoint=?1",
            [checkpoint],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                ))
            },
        )
        .map_err(|error| format!("governed-repair-scope-read:{error}"))
        .and_then(
            |(
                delta_digest,
                effect_class,
                resources,
                blocked_effect_class,
                blocked_resource,
                blocked_path,
                blocked_operation,
                reason,
                evidence,
                limitations,
            )| {
                Ok(
                    SealedGovernedRepairRequirementWireV1::ScopeExpansionRequired(
                        ScopeExpansionRequiredWireV1 {
                            schema: SCOPE_EXPANSION_REQUIRED_SCHEMA_V1.to_owned(),
                            requirement_identity: identity.to_owned(),
                            binding,
                            requested_delta: RequestedEffectDeltaWireV1 {
                                schema: gwr_core::governed_repair::CANONICAL_EFFECT_SCOPE_SCHEMA_V1
                                    .to_owned(),
                                effect_class,
                                resources: decode_resources(&resources)?,
                            },
                            requested_delta_digest: delta_digest,
                            blocked_effect: BlockedEffectWireV1 {
                                effect_class: blocked_effect_class,
                                resource: blocked_resource,
                                path: blocked_path,
                                operation: parse_operation(&blocked_operation)?,
                            },
                            reason,
                            dependency_evidence: split_list(&evidence)?,
                            no_unauthorized_effect_reported: true,
                            limitations: split_list(&limitations)?,
                        },
                    ),
                )
            },
        )
}

fn read_readjudication(
    connection: &Connection,
    checkpoint: &str,
    binding: GovernedRepairBindingWireV1,
    identity: &str,
) -> Result<SealedGovernedRepairRequirementWireV1, String> {
    connection
        .query_row(
            "SELECT question,evidence_census,diagnostic_census,bounded_alternatives,
        unresolved_facts,adjudication_scope,limitations FROM governed_repair_readjudication WHERE checkpoint=?1",
            [checkpoint],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .map_err(|error| format!("governed-repair-readjudication-read:{error}"))
        .and_then(
            |(question, evidence, diagnostics, alternatives, facts, scope, limitations)| {
                Ok(
                    SealedGovernedRepairRequirementWireV1::ReadjudicationRequired(
                        ReadjudicationRequiredWireV1 {
                            schema: READJUDICATION_REQUIRED_SCHEMA_V1.to_owned(),
                            requirement_identity: identity.to_owned(),
                            binding,
                            question,
                            evidence_census: split_list(&evidence)?,
                            diagnostic_census: split_list(&diagnostics)?,
                            bounded_alternatives: split_list(&alternatives)?,
                            unresolved_facts: split_list(&facts)?,
                            adjudication_scope: decode_scope(&scope)?,
                            no_unauthorized_effect_reported: true,
                            limitations: split_list(&limitations)?,
                        },
                    ),
                )
            },
        )
}

pub(crate) fn validate_read_result(
    result: &StoreSealedGovernedRepairResultV1,
    issuance: &AgIssuanceWireV2,
    journal: &[EffectJournalEntryWireV1],
) -> Result<(), String> {
    validate_ag_effect_scope_identity(&issuance.effect_scope, &issuance.effect_scope_digest)?;
    if let SealedGovernedRepairRequirementWireV1::ScopeExpansionRequired(value) = &result.outcome {
        validate_ag_effect_scope_identity(&value.requested_delta, &value.requested_delta_digest)?;
    }
    let binding = outcome_binding(&result.outcome);
    if result.schema != SEALED_GOVERNED_REPAIR_RESULT_SCHEMA_V1
        || result.checkpoint.schema != GOVERNED_REPAIR_CHECKPOINT_SCHEMA_V1
        || result.checkpoint.issuance != issuance.issuance
        || binding.campaign != issuance.key.campaign
        || binding.occurrence != issuance.key.occurrence
        || binding.proposal != issuance.proposal
        || binding.observation != issuance.observation
        || binding.standing_resolution != issuance.standing_resolution
        || binding.admission_decision != issuance.admission_decision.decision
        || binding.spend != issuance.spend
        || binding.original_scope != issuance.effect_scope
        || binding.original_scope_digest != issuance.effect_scope_digest
        || binding.issuance != issuance.issuance
        || binding.custody != result.checkpoint.custody
        || binding.attempt != result.checkpoint.attempt
        || binding.executor_binding != result.checkpoint.executor_binding
        || binding.executor_result != result.checkpoint.executor_result
        || binding.effect_journal_digest != result.checkpoint.effect_journal_digest
        || binding.idempotency != result.checkpoint.idempotency
        || binding.created_at_unix_ms != result.checkpoint.created_at_unix_ms
        || binding.expires_at_unix_ms != result.checkpoint.expires_at_unix_ms
    {
        return Err("governed-repair-stored-binding-substitution".to_owned());
    }
    if executor_result_identity(
        &result.checkpoint.executor_receipt,
        &outcome_to_draft(&result.outcome),
        journal,
        result.checkpoint.immutable_work_checkpoint.as_ref(),
    )? != result.checkpoint.executor_result
    {
        return Err("governed-repair-executor-result-substitution".to_owned());
    }
    if validate_effect_journal(&issuance.effect_scope, journal)?
        != result.checkpoint.effect_journal_digest
        || binding.reported_authorized_effects_occurred == journal.is_empty()
    {
        return Err("governed-repair-stored-journal-substitution".to_owned());
    }
    let requirement = wire_to_core_requirement(&result.outcome)?;
    let expected_requirement = qualified(
        requirement
            .validate(binding.created_at_unix_ms)
            .map_err(|refusal| format!("governed-repair-stored-refused:{refusal:?}"))?,
    );
    if expected_requirement != result.checkpoint.requirement_identity
        || expected_requirement != outcome_identity(&result.outcome)
        || requirement.kind() != result.checkpoint.requirement_kind
    {
        return Err("governed-repair-requirement-substitution".to_owned());
    }
    if checkpoint_identity(
        &result.checkpoint.issuance,
        &result.checkpoint.custody,
        &result.checkpoint.attempt,
        &result.checkpoint.executor_binding,
        &result.checkpoint.executor_result,
        &result.checkpoint.executor_receipt,
        &result.checkpoint.requirement_kind,
        &result.checkpoint.requirement_identity,
        &result.checkpoint.effect_journal_digest,
        result.checkpoint.immutable_work_checkpoint.as_ref(),
        &result.checkpoint.idempotency,
        result.checkpoint.created_at_unix_ms,
        result.checkpoint.expires_at_unix_ms,
    ) != result.checkpoint.checkpoint
    {
        return Err("governed-repair-checkpoint-substitution".to_owned());
    }
    if result.sealed_result != sealed_result_identity(&result.checkpoint) {
        return Err("governed-repair-sealed-result-substitution".to_owned());
    }
    Ok(())
}

fn wire_to_core_requirement(
    value: &SealedGovernedRepairRequirementWireV1,
) -> Result<GovernedRepairRequirementV1, String> {
    Ok(match value {
        SealedGovernedRepairRequirementWireV1::ScopeExpansionRequired(value) => {
            GovernedRepairRequirementV1::ScopeExpansion(ScopeExpansionRequiredV1 {
                binding: to_core_binding(&value.binding)?,
                requested_delta: to_core_delta(&value.requested_delta),
                requested_delta_digest: parse_digest(&value.requested_delta_digest)?,
                blocked_effect: BlockedEffectV1 {
                    effect_class: value.blocked_effect.effect_class.clone(),
                    resource: value.blocked_effect.resource.clone(),
                    path: value.blocked_effect.path.clone(),
                    operation: to_core_operation(value.blocked_effect.operation),
                },
                reason: parse_digest(&value.reason)?,
                dependency_evidence: parse_digests(&value.dependency_evidence)?,
                no_unauthorized_effect_reported: value.no_unauthorized_effect_reported,
                limitations: parse_digests(&value.limitations)?,
            })
        }
        SealedGovernedRepairRequirementWireV1::ReadjudicationRequired(value) => {
            GovernedRepairRequirementV1::Readjudication(ReadjudicationRequiredV1 {
                binding: to_core_binding(&value.binding)?,
                question: parse_digest(&value.question)?,
                evidence_census: parse_digests(&value.evidence_census)?,
                diagnostic_census: parse_digests(&value.diagnostic_census)?,
                bounded_alternatives: parse_digests(&value.bounded_alternatives)?,
                unresolved_facts: parse_digests(&value.unresolved_facts)?,
                adjudication_scope: to_core_scope(&value.adjudication_scope),
                no_unauthorized_effect_reported: value.no_unauthorized_effect_reported,
                limitations: parse_digests(&value.limitations)?,
            })
        }
    })
}

fn outcome_identity(value: &SealedGovernedRepairRequirementWireV1) -> &str {
    match value {
        SealedGovernedRepairRequirementWireV1::ScopeExpansionRequired(value) => {
            &value.requirement_identity
        }
        SealedGovernedRepairRequirementWireV1::ReadjudicationRequired(value) => {
            &value.requirement_identity
        }
    }
}

fn outcome_to_draft(
    value: &SealedGovernedRepairRequirementWireV1,
) -> ExecutorGovernedRepairRequirementWireV1 {
    match value {
        SealedGovernedRepairRequirementWireV1::ScopeExpansionRequired(value) => {
            ExecutorGovernedRepairRequirementWireV1::ScopeExpansionRequired {
                requested_delta: value.requested_delta.clone(),
                requested_delta_digest: value.requested_delta_digest.clone(),
                blocked_effect: value.blocked_effect.clone(),
                reason: value.reason.clone(),
                dependency_evidence: value.dependency_evidence.clone(),
                created_at_unix_ms: value.binding.created_at_unix_ms,
                expires_at_unix_ms: value.binding.expires_at_unix_ms,
                idempotency: value.binding.idempotency.clone(),
                limitations: value.limitations.clone(),
            }
        }
        SealedGovernedRepairRequirementWireV1::ReadjudicationRequired(value) => {
            ExecutorGovernedRepairRequirementWireV1::ReadjudicationRequired {
                question: value.question.clone(),
                evidence_census: value.evidence_census.clone(),
                diagnostic_census: value.diagnostic_census.clone(),
                bounded_alternatives: value.bounded_alternatives.clone(),
                unresolved_facts: value.unresolved_facts.clone(),
                adjudication_scope: value.adjudication_scope.clone(),
                created_at_unix_ms: value.binding.created_at_unix_ms,
                expires_at_unix_ms: value.binding.expires_at_unix_ms,
                idempotency: value.binding.idempotency.clone(),
                limitations: value.limitations.clone(),
            }
        }
    }
}

fn parse_digest(value: &str) -> Result<Sha256Digest, String> {
    Sha256Digest::parse_qualified(value).ok_or_else(|| "governed-repair-digest".to_owned())
}
fn parse_digests(values: &[String]) -> Result<Vec<Sha256Digest>, String> {
    values.iter().map(|value| parse_digest(value)).collect()
}
fn qualified(value: Sha256Digest) -> String {
    format!("sha256:{}", value.to_hex())
}
pub(crate) fn ag_custody_reference(value: &DocketCustodyWireV1) -> Result<String, String> {
    ag_jcs_identity("ag.governed-loop.docket-custody/v1", value)
}

fn executor_result_identity(
    receipt: &str,
    draft: &ExecutorGovernedRepairRequirementWireV1,
    journal: &[EffectJournalEntryWireV1],
    work: Option<&ImmutableWorkCheckpointWireV1>,
) -> Result<String, String> {
    let (kind, created, expires, idempotency) = match draft {
        ExecutorGovernedRepairRequirementWireV1::ScopeExpansionRequired {
            created_at_unix_ms,
            expires_at_unix_ms,
            idempotency,
            ..
        } => (
            "scope_expansion_required",
            created_at_unix_ms,
            expires_at_unix_ms,
            idempotency,
        ),
        ExecutorGovernedRepairRequirementWireV1::ReadjudicationRequired {
            created_at_unix_ms,
            expires_at_unix_ms,
            idempotency,
            ..
        } => (
            "readjudication_required",
            created_at_unix_ms,
            expires_at_unix_ms,
            idempotency,
        ),
    };
    let mut transcript = Transcript::new("docket.governed-loop.executor-result/v1")
        .text_field("receipt", receipt)
        .text_field("kind", kind)
        .text_field("idempotency", idempotency)
        .text_field("created_at_unix_ms", &created.to_string())
        .text_field("expires_at_unix_ms", &expires.to_string())
        .text_field("journal", &validate_effect_journal_unscoped(journal)?);
    transcript = match draft {
        ExecutorGovernedRepairRequirementWireV1::ScopeExpansionRequired {
            requested_delta,
            requested_delta_digest,
            blocked_effect,
            reason,
            dependency_evidence,
            limitations,
            ..
        } => {
            validate_ag_effect_scope_identity(requested_delta, requested_delta_digest)?;
            let mut value = transcript
                .text_field("requested_delta", requested_delta_digest)
                .text_field("blocked_effect_class", &blocked_effect.effect_class)
                .text_field("blocked_resource", &blocked_effect.resource)
                .text_field("blocked_path", &blocked_effect.path)
                .text_field("blocked_operation", operation_tag(blocked_effect.operation))
                .text_field("reason", reason);
            for identity in dependency_evidence {
                parse_digest(identity)?;
                value = value.text_field("dependency_evidence", identity);
            }
            for limitation in limitations {
                value = value.text_field("limitation", limitation);
            }
            value
        }
        ExecutorGovernedRepairRequirementWireV1::ReadjudicationRequired {
            question,
            evidence_census,
            diagnostic_census,
            bounded_alternatives,
            unresolved_facts,
            adjudication_scope,
            limitations,
            ..
        } => {
            parse_digest(question)?;
            let mut value = transcript.text_field("question", question).text_field(
                "adjudication_scope",
                &ag_jcs_identity(
                    "ag.governed-loop.canonical-effect-scope/v1",
                    adjudication_scope,
                )?,
            );
            for identity in evidence_census {
                parse_digest(identity)?;
                value = value.text_field("evidence", identity);
            }
            for identity in diagnostic_census {
                parse_digest(identity)?;
                value = value.text_field("diagnostic", identity);
            }
            for alternative in bounded_alternatives {
                parse_digest(alternative)?;
                value = value.text_field("alternative", alternative);
            }
            for fact in unresolved_facts {
                parse_digest(fact)?;
                value = value.text_field("unresolved_fact", fact);
            }
            for limitation in limitations {
                parse_digest(limitation)?;
                value = value.text_field("limitation", limitation);
            }
            value
        }
    };
    if let Some(work) = work {
        transcript = work_checkpoint_transcript(transcript, work);
    }
    Ok(qualified(transcript.finalize()))
}

#[allow(clippy::too_many_arguments)]
fn checkpoint_identity(
    issuance: &str,
    custody: &str,
    attempt: &str,
    executor_binding: &str,
    executor_result: &str,
    executor_receipt: &str,
    kind: &str,
    requirement: &str,
    journal: &str,
    work: Option<&ImmutableWorkCheckpointWireV1>,
    idempotency: &str,
    created: u64,
    expires: u64,
) -> String {
    let mut transcript = Transcript::new("docket.governed-repair.checkpoint/v1")
        .text_field("issuance", issuance)
        .text_field("custody", custody)
        .text_field("attempt", attempt)
        .text_field("executor_binding", executor_binding)
        .text_field("executor_result", executor_result)
        .text_field("executor_receipt", executor_receipt)
        .text_field("requirement_kind", kind)
        .text_field("requirement_identity", requirement)
        .text_field("effect_journal", journal)
        .text_field("idempotency", idempotency)
        .text_field("created_at_unix_ms", &created.to_string())
        .text_field("expires_at_unix_ms", &expires.to_string());
    if let Some(work) = work {
        transcript = work_checkpoint_transcript(transcript, work);
    }
    qualified(transcript.finalize())
}

fn sealed_result_identity(checkpoint: &GovernedRepairCheckpointWireV1) -> String {
    qualified(
        Transcript::new("docket.governed-repair.sealed-result/v1")
            .text_field("checkpoint", &checkpoint.checkpoint)
            .text_field("issuance", &checkpoint.issuance)
            .text_field("custody", &checkpoint.custody)
            .text_field("attempt", &checkpoint.attempt)
            .text_field("outcome_kind", &checkpoint.requirement_kind)
            .text_field("outcome_identity", &checkpoint.requirement_identity)
            .text_field(
                "created_at_unix_ms",
                &checkpoint.created_at_unix_ms.to_string(),
            )
            .text_field(
                "expires_at_unix_ms",
                &checkpoint.expires_at_unix_ms.to_string(),
            )
            .finalize(),
    )
}

fn work_checkpoint_transcript(
    transcript: Transcript,
    work: &ImmutableWorkCheckpointWireV1,
) -> Transcript {
    transcript
        .text_field("work_repository", &work.repository_identity)
        .text_field("work_commit", &work.commit)
        .text_field("work_tree", &work.tree)
        .text_field("work_diff", work.diff_identity.as_deref().unwrap_or(""))
        .text_field("work_content_manifest", &work.content_manifest_identity)
}

fn validate_effect_journal_unscoped(
    entries: &[EffectJournalEntryWireV1],
) -> Result<String, String> {
    let mut transcript = Transcript::new("docket.governed-loop.effect-journal/v1");
    for entry in entries {
        parse_digest(&entry.effect_identity)?;
        transcript = transcript
            .text_field("resource", &entry.resource)
            .text_field("path", &entry.path)
            .text_field("operation", operation_tag(entry.operation))
            .text_field("effect_identity", &entry.effect_identity);
    }
    Ok(qualified(transcript.finalize()))
}
/// Reproduce an upstream AG JCS-compatible identity at the interop boundary.
/// Docket-owned identities below use explicit `Transcript` fields instead.
fn ag_jcs_identity<T: Serialize + ?Sized>(domain: &str, value: &T) -> Result<String, String> {
    let value = serde_json::to_value(value)
        .map_err(|error| format!("governed-repair-canonical:{error}"))?;
    validate_safe_json_value(&value)?;
    let bytes =
        serde_jcs::to_vec(&value).map_err(|error| format!("governed-repair-canonical:{error}"))?;
    Ok(hash_domain(domain, &bytes))
}

fn validate_safe_json_value(value: &serde_json::Value) -> Result<(), String> {
    match value {
        serde_json::Value::Number(number) => {
            const LIMIT: u64 = 9_007_199_254_740_991;
            if number.as_u64().is_some_and(|value| value <= LIMIT)
                || number
                    .as_i64()
                    .is_some_and(|value| value >= -(LIMIT as i64) && value <= LIMIT as i64)
            {
                Ok(())
            } else {
                Err("governed-repair-number-outside-jcs-safe-integer-domain".to_owned())
            }
        }
        serde_json::Value::Array(values) => values.iter().try_for_each(validate_safe_json_value),
        serde_json::Value::Object(values) => values.values().try_for_each(validate_safe_json_value),
        _ => Ok(()),
    }
}
pub(crate) fn validate_ag_effect_scope_identity(
    value: &CanonicalEffectScopeWireV1,
    expected: &str,
) -> Result<(), String> {
    to_core_scope(value)
        .validate()
        .map_err(|refusal| format!("governed-repair-effect-scope:{refusal:?}"))?;
    if ag_jcs_identity("ag.governed-loop.canonical-effect-scope/v1", value)? != expected {
        return Err("governed-repair-effect-scope-identity".to_owned());
    }
    Ok(())
}
fn validate_effect_journal(
    scope: &CanonicalEffectScopeWireV1,
    entries: &[EffectJournalEntryWireV1],
) -> Result<String, String> {
    for entry in entries {
        parse_digest(&entry.effect_identity)?;
        let admitted = scope.resources.iter().any(|resource| {
            resource.resource == entry.resource
                && resource.path == entry.path
                && resource.operations.contains(&entry.operation)
        });
        if !admitted {
            return Err("governed-repair-unauthorized-effect-observed".to_owned());
        }
    }
    validate_effect_journal_unscoped(entries)
}

pub(crate) fn validate_effect_journal_for_issuance(
    scope: &CanonicalEffectScopeWireV1,
    entries: &[EffectJournalEntryWireV1],
) -> Result<String, String> {
    validate_effect_journal(scope, entries)
}

pub(crate) struct OrdinaryExecutorResultInputV1<'a> {
    pub issuance: &'a str,
    pub attempt: &'a str,
    pub outcome: &'a str,
    pub receipt: &'a str,
    pub scope: &'a CanonicalEffectScopeWireV1,
    pub entries: &'a [EffectJournalEntryWireV1],
    pub recorded_at: u64,
}

/// Backfills the R2 cumulative journal columns from the immutable pre-R2
/// observation order. This is evidence migration only; it creates no custody,
/// standing, or executor result.
pub(crate) fn backfill_cumulative_executor_journals(connection: &Connection) -> Result<(), String> {
    let rows: Vec<(i64, String, String)> = connection
        .prepare(
            "SELECT sequence,issuance,effect_journal_entries
             FROM governed_executor_result ORDER BY sequence",
        )
        .map_err(|error| format!("governed-cumulative-migration-read:{error}"))?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .map_err(|error| format!("governed-cumulative-migration-read:{error}"))?
        .collect::<Result<_, _>>()
        .map_err(|error| format!("governed-cumulative-migration-read:{error}"))?;
    let mut cumulative: BTreeMap<String, Vec<EffectJournalEntryWireV1>> = BTreeMap::new();
    for (sequence, issuance, encoded) in rows {
        let entries = decode_journal(&encoded)?;
        let aggregate = cumulative.entry(issuance).or_default();
        merge_effect_journal(aggregate, &entries)?;
        let aggregate_encoded = encode_journal(aggregate);
        let aggregate_digest = validate_effect_journal_unscoped(aggregate)?;
        connection
            .execute(
                "UPDATE governed_executor_result
                 SET cumulative_effect_journal_digest=?1,
                     cumulative_effect_journal_entries=?2
                 WHERE sequence=?3",
                params![aggregate_digest, aggregate_encoded, sequence],
            )
            .map_err(|error| format!("governed-cumulative-migration-write:{error}"))?;
    }
    // A pre-R2 terminal governed-repair result cannot be rewritten safely:
    // its journal participates in executor-result, requirement, checkpoint,
    // and sealed-result identities. Verify that any prior ordinary effects
    // were already included in the terminal journal; otherwise fail the whole
    // migration transaction instead of opening a store with false lineage.
    let terminal_rows: Vec<(String, String)> = connection
        .prepare(
            "SELECT issuance,effect_journal_entries
             FROM governed_repair_checkpoint ORDER BY issuance",
        )
        .map_err(|error| format!("governed-cumulative-migration-terminal-read:{error}"))?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(|error| format!("governed-cumulative-migration-terminal-read:{error}"))?
        .collect::<Result<_, _>>()
        .map_err(|error| format!("governed-cumulative-migration-terminal-read:{error}"))?;
    for (issuance, terminal_encoded) in terminal_rows {
        let terminal = decode_journal(&terminal_encoded)?;
        let mut complete = cumulative.get(&issuance).cloned().unwrap_or_default();
        merge_effect_journal(&mut complete, &terminal)?;
        if complete != terminal {
            return Err("governed-cumulative-migration-terminal-journal-incomplete".to_owned());
        }
    }
    Ok(())
}

fn prior_cumulative_effect_journal(
    connection: &Connection,
    issuance: &str,
    attempt: &str,
) -> Result<Vec<EffectJournalEntryWireV1>, String> {
    let encoded: Option<String> = connection
        .query_row(
            "SELECT cumulative_effect_journal_entries
             FROM governed_executor_result
             WHERE issuance=?1 AND attempt=?2 ORDER BY sequence DESC LIMIT 1",
            params![issuance, attempt],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| format!("governed-cumulative-journal-read:{error}"))?;
    encoded.map_or_else(|| Ok(Vec::new()), |value| decode_journal(&value))
}

pub(crate) fn cumulative_effect_journal_with(
    connection: &Connection,
    issuance: &str,
    attempt: &str,
    entries: &[EffectJournalEntryWireV1],
) -> Result<Vec<EffectJournalEntryWireV1>, String> {
    let mut cumulative = prior_cumulative_effect_journal(connection, issuance, attempt)?;
    merge_effect_journal(&mut cumulative, entries)?;
    Ok(cumulative)
}

/// Returns the exact cumulative journal identity at the latest durable
/// executor-observation cut. The stored entries are revalidated rather than
/// trusting the digest column in isolation.
pub(crate) fn latest_cumulative_effect_journal_identity(
    connection: &Connection,
    issuance: &str,
    attempt: &str,
    scope: &CanonicalEffectScopeWireV1,
) -> Result<Option<String>, String> {
    let stored: Option<(String, String)> = connection
        .query_row(
            "SELECT cumulative_effect_journal_digest,cumulative_effect_journal_entries
             FROM governed_executor_result
             WHERE issuance=?1 AND attempt=?2 ORDER BY sequence DESC LIMIT 1",
            params![issuance, attempt],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| format!("governed-cumulative-journal-identity-read:{error}"))?;
    stored
        .map(|(identity, encoded)| {
            let entries = decode_journal(&encoded)?;
            if validate_effect_journal(scope, &entries)? != identity {
                return Err("governed-executor-cumulative-journal-substitution".to_owned());
            }
            Ok(identity)
        })
        .transpose()
}

/// Extends one occurrence's ordered cumulative journal. A later observation
/// may repeat an already reported exact effect without inventing a second
/// occurrence, but reusing an effect identity with different coordinates is a
/// replay contradiction and fails closed.
fn merge_effect_journal(
    cumulative: &mut Vec<EffectJournalEntryWireV1>,
    entries: &[EffectJournalEntryWireV1],
) -> Result<(), String> {
    for entry in entries {
        if let Some(existing) = cumulative
            .iter()
            .find(|existing| existing.effect_identity == entry.effect_identity)
        {
            if existing != entry {
                return Err("governed-executor-effect-identity-collision".to_owned());
            }
            continue;
        }
        cumulative.push(entry.clone());
    }
    Ok(())
}

pub(crate) fn append_ordinary_executor_result(
    tx: &Transaction<'_>,
    input: OrdinaryExecutorResultInputV1<'_>,
) -> Result<bool, String> {
    let OrdinaryExecutorResultInputV1 {
        issuance,
        attempt,
        outcome,
        receipt,
        scope,
        entries,
        recorded_at,
    } = input;
    parse_digest(receipt)?;
    let journal = validate_effect_journal(scope, entries)?;
    let identity = qualified(
        Transcript::new("docket.governed-loop.executor-result/v1")
            .text_field("issuance", issuance)
            .text_field("attempt", attempt)
            .text_field("outcome", outcome)
            .text_field("receipt", receipt)
            .text_field("effect_journal", &journal)
            .finalize(),
    );
    let existing: Option<(String, String, String, String)> = tx
        .query_row(
            "SELECT result_identity,outcome,effect_journal_digest,effect_journal_entries
             FROM governed_executor_result
             WHERE issuance=?1 AND receipt=?2",
            params![issuance, receipt],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|error| format!("governed-executor-result-read:{error}"))?;
    let encoded = encode_journal(entries);
    if let Some(existing) = existing {
        return if existing == (identity.clone(), outcome.to_owned(), journal, encoded) {
            Ok(true)
        } else {
            Err("governed-executor-result-replay-collision".to_owned())
        };
    }
    let (status, checkpoint_exists): (String, i64) = tx
        .query_row(
            "SELECT status,
                    EXISTS(SELECT 1 FROM governed_repair_checkpoint WHERE issuance=?1)
             FROM governed_loop_attempt WHERE issuance=?1 AND attempt=?2",
            params![issuance, attempt],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| format!("governed-executor-result-terminal-read:{error}"))?;
    if !matches!(status.as_str(), "accepted" | "indeterminate") || checkpoint_exists != 0 {
        return Err("governed-executor-result-after-terminal".to_owned());
    }
    let cumulative = cumulative_effect_journal_with(tx, issuance, attempt, entries)?;
    let cumulative_journal = validate_effect_journal(scope, &cumulative)?;
    let cumulative_encoded = encode_journal(&cumulative);
    tx.execute(
        "INSERT INTO governed_executor_result
         (issuance,attempt,result_identity,outcome,receipt,effect_journal_digest,effect_journal_entries,
          cumulative_effect_journal_digest,cumulative_effect_journal_entries,recorded_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![issuance, attempt, identity, outcome, receipt, journal, encoded,
            cumulative_journal, cumulative_encoded, to_i64(recorded_at)?],
    )
    .map_err(|error| format!("governed-executor-result-write:{error}"))?;
    Ok(false)
}

pub(crate) fn validate_ordinary_executor_result(
    connection: &Connection,
    issuance: &str,
    attempt: &str,
    status: &str,
    scope: &CanonicalEffectScopeWireV1,
) -> Result<(), String> {
    let rows: Vec<(String, String, String, String, String, String, String)> = connection
        .prepare(
            "SELECT result_identity,outcome,receipt,effect_journal_digest,effect_journal_entries,
                    cumulative_effect_journal_digest,cumulative_effect_journal_entries
             FROM governed_executor_result WHERE issuance=?1 AND attempt=?2 ORDER BY sequence",
        )
        .map_err(|error| format!("governed-executor-result-read:{error}"))?
        .query_map(params![issuance, attempt], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        })
        .map_err(|error| format!("governed-executor-result-read:{error}"))?
        .collect::<Result<_, _>>()
        .map_err(|error| format!("governed-executor-result-read:{error}"))?;
    if status == "accepted" {
        return if rows.is_empty() {
            Ok(())
        } else {
            Err("governed-executor-result-before-terminal".to_owned())
        };
    }
    if rows.is_empty() {
        return Err("governed-executor-result-missing".to_owned());
    }
    let mut cumulative = Vec::new();
    for (
        identity,
        outcome,
        receipt,
        journal_identity,
        encoded,
        cumulative_identity,
        cumulative_encoded,
    ) in &rows
    {
        let entries = decode_journal(encoded)?;
        if validate_effect_journal(scope, &entries)? != *journal_identity {
            return Err("governed-executor-journal-substitution".to_owned());
        }
        let expected = qualified(
            Transcript::new("docket.governed-loop.executor-result/v1")
                .text_field("issuance", issuance)
                .text_field("attempt", attempt)
                .text_field("outcome", outcome)
                .text_field("receipt", receipt)
                .text_field("effect_journal", journal_identity)
                .finalize(),
        );
        if expected != *identity
            || !matches!(outcome.as_str(), "success" | "failure" | "indeterminate")
        {
            return Err("governed-executor-result-substitution".to_owned());
        }
        merge_effect_journal(&mut cumulative, &entries)?;
        if decode_journal(cumulative_encoded)? != cumulative
            || validate_effect_journal(scope, &cumulative)? != *cumulative_identity
        {
            return Err("governed-executor-cumulative-journal-substitution".to_owned());
        }
    }
    let final_outcome = &rows
        .last()
        .ok_or_else(|| "governed-executor-result-missing".to_owned())?
        .1;
    let terminal_count = rows
        .iter()
        .filter(|row| matches!(row.1.as_str(), "success" | "failure"))
        .count();
    if terminal_count > 1 {
        return Err("governed-executor-multiple-terminal-results".to_owned());
    }
    if (status == "settled" && final_outcome == "indeterminate")
        || (status == "indeterminate" && final_outcome != "indeterminate")
    {
        return Err("governed-executor-result-status-substitution".to_owned());
    }
    Ok(())
}

fn validate_work_checkpoint(value: &ImmutableWorkCheckpointWireV1) -> Result<(), String> {
    parse_digest(&value.repository_identity)?;
    for (object, label) in [(&value.commit, "commit"), (&value.tree, "tree")] {
        if object.len() != 40
            || !object
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(format!("governed-repair-work-checkpoint-{label}"));
        }
    }
    if let Some(identity) = &value.diff_identity {
        parse_digest(identity)?;
    }
    parse_digest(&value.content_manifest_identity)?;
    Ok(())
}
fn hash_domain(domain: &str, payload: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"ag-ng\0digest\0v1\0");
    h.update((domain.len() as u128).to_be_bytes());
    h.update(domain.as_bytes());
    h.update((payload.len() as u128).to_be_bytes());
    h.update(payload);
    format!("sha256:{}", lower_hex(&h.finalize()))
}
fn lower_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}
fn join_list(values: &[String]) -> String {
    let mut out = String::new();
    for value in values {
        out.push_str(&value.len().to_string());
        out.push(':');
        out.push_str(value);
    }
    out
}
fn split_list(value: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut rest = value;
    while !rest.is_empty() {
        let colon = rest
            .find(':')
            .ok_or_else(|| "governed-repair-list-corrupt".to_owned())?;
        let len: usize = rest[..colon]
            .parse()
            .map_err(|_| "governed-repair-list-corrupt".to_owned())?;
        let body = &rest[colon + 1..];
        if body.len() < len || !body.is_char_boundary(len) {
            return Err("governed-repair-list-corrupt".to_owned());
        }
        out.push(body[..len].to_owned());
        rest = &body[len..];
    }
    Ok(out)
}
fn encode_resources(values: &[crate::governed_loop::CanonicalEffectResourceWireV1]) -> String {
    let rows: Vec<String> = values
        .iter()
        .map(|value| {
            let mut fields = vec![value.resource.clone(), value.path.clone()];
            fields.extend(
                value
                    .operations
                    .iter()
                    .map(|operation| operation_tag(*operation).to_owned()),
            );
            join_list(&fields)
        })
        .collect();
    join_list(&rows)
}
fn decode_resources(
    value: &str,
) -> Result<Vec<crate::governed_loop::CanonicalEffectResourceWireV1>, String> {
    split_list(value)?
        .into_iter()
        .map(|row| {
            let fields = split_list(&row)?;
            if fields.len() < 3 {
                return Err("governed-repair-resource-corrupt".to_owned());
            }
            Ok(crate::governed_loop::CanonicalEffectResourceWireV1 {
                resource: fields[0].clone(),
                path: fields[1].clone(),
                operations: fields[2..]
                    .iter()
                    .map(|value| parse_operation(value))
                    .collect::<Result<_, _>>()?,
            })
        })
        .collect()
}

fn encode_scope(value: &CanonicalEffectScopeWireV1) -> String {
    join_list(&[
        value.schema.clone(),
        value.effect_class.clone(),
        encode_resources(&value.resources),
    ])
}

fn decode_scope(value: &str) -> Result<CanonicalEffectScopeWireV1, String> {
    let fields = split_list(value)?;
    let [schema, effect_class, resources] = fields.as_slice() else {
        return Err("governed-repair-scope-corrupt".to_owned());
    };
    Ok(CanonicalEffectScopeWireV1 {
        schema: schema.clone(),
        effect_class: effect_class.clone(),
        resources: decode_resources(resources)?,
    })
}

fn encode_journal(values: &[EffectJournalEntryWireV1]) -> String {
    let rows: Vec<String> = values
        .iter()
        .map(|value| {
            join_list(&[
                value.resource.clone(),
                value.path.clone(),
                operation_tag(value.operation).to_owned(),
                value.effect_identity.clone(),
            ])
        })
        .collect();
    join_list(&rows)
}

fn decode_journal(value: &str) -> Result<Vec<EffectJournalEntryWireV1>, String> {
    split_list(value)?
        .into_iter()
        .map(|row| {
            let fields = split_list(&row)?;
            let [resource, path, operation, effect_identity] = fields.as_slice() else {
                return Err("governed-repair-journal-corrupt".to_owned());
            };
            parse_digest(effect_identity)?;
            Ok(EffectJournalEntryWireV1 {
                resource: resource.clone(),
                path: path.clone(),
                operation: parse_operation(operation)?,
                effect_identity: effect_identity.clone(),
            })
        })
        .collect()
}

#[cfg(test)]
pub(crate) fn decode_journal_for_test(
    value: &str,
) -> Result<Vec<EffectJournalEntryWireV1>, String> {
    decode_journal(value)
}

fn decode_base64url(value: &str) -> Result<Vec<u8>, String> {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut acc = 0_u32;
    let mut bits = 0_u32;
    let mut out = Vec::new();
    for byte in value.bytes() {
        let index = A
            .iter()
            .position(|x| *x == byte)
            .ok_or_else(|| "governed-repair-base64".to_owned())? as u32;
        acc = (acc << 6) | index;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if bits >= 6 || (acc & ((1 << bits) - 1)) != 0 {
        return Err("governed-repair-base64".to_owned());
    }
    Ok(out)
}
fn to_i64(value: u64) -> Result<i64, String> {
    if value > 9_007_199_254_740_991 {
        return Err("governed-repair-time-outside-jcs-safe-integer-domain".to_owned());
    }
    i64::try_from(value).map_err(|_| "governed-repair-time-range".to_owned())
}
fn to_u64(value: i64) -> Result<u64, String> {
    let value = u64::try_from(value).map_err(|_| "governed-repair-time-corrupt".to_owned())?;
    if value > 9_007_199_254_740_991 {
        return Err("governed-repair-time-outside-jcs-safe-integer-domain".to_owned());
    }
    Ok(value)
}

#[cfg(test)]
mod wire_tests {
    use super::*;

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn checkpoint(work: Option<ImmutableWorkCheckpointWireV1>) -> GovernedRepairCheckpointWireV1 {
        GovernedRepairCheckpointWireV1 {
            schema: GOVERNED_REPAIR_CHECKPOINT_SCHEMA_V1.to_owned(),
            checkpoint: digest('1'),
            issuance: digest('2'),
            custody: digest('3'),
            attempt: digest('4'),
            executor_binding: digest('5'),
            executor_result: digest('6'),
            executor_receipt: digest('7'),
            requirement_kind: "scope_expansion_required".to_owned(),
            requirement_identity: digest('8'),
            effect_journal_digest: digest('9'),
            immutable_work_checkpoint: work,
            idempotency: digest('a'),
            created_at_unix_ms: 1,
            expires_at_unix_ms: 2,
        }
    }

    #[test]
    fn work_checkpoint_optionals_are_omitted_and_explicit_null_refuses() {
        let absent = serde_json::to_value(checkpoint(None)).unwrap();
        assert!(!absent
            .as_object()
            .unwrap()
            .contains_key("immutable_work_checkpoint"));
        let mut explicit_null = absent;
        explicit_null["immutable_work_checkpoint"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<GovernedRepairCheckpointWireV1>(explicit_null).is_err());

        let present = checkpoint(Some(ImmutableWorkCheckpointWireV1 {
            repository_identity: digest('b'),
            commit: "1".repeat(40),
            tree: "2".repeat(40),
            diff_identity: None,
            content_manifest_identity: digest('c'),
        }));
        let mut value = serde_json::to_value(&present).unwrap();
        let work = value["immutable_work_checkpoint"].as_object().unwrap();
        assert!(!work.contains_key("diff_identity"));
        assert!(work.contains_key("content_manifest_identity"));
        value["immutable_work_checkpoint"]["diff_identity"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<GovernedRepairCheckpointWireV1>(value).is_err());

        let mut missing_manifest = serde_json::to_value(present).unwrap();
        missing_manifest["immutable_work_checkpoint"]
            .as_object_mut()
            .unwrap()
            .remove("content_manifest_identity");
        assert!(
            serde_json::from_value::<GovernedRepairCheckpointWireV1>(missing_manifest).is_err()
        );
    }

    #[test]
    fn persisted_governed_repair_times_use_the_jcs_safe_integer_domain() {
        assert_eq!(
            to_i64(9_007_199_254_740_991).unwrap(),
            9_007_199_254_740_991
        );
        assert_eq!(
            to_i64(9_007_199_254_740_992).unwrap_err(),
            "governed-repair-time-outside-jcs-safe-integer-domain"
        );
        assert_eq!(
            to_u64(9_007_199_254_740_991).unwrap(),
            9_007_199_254_740_991
        );
        assert_eq!(
            to_u64(9_007_199_254_740_992).unwrap_err(),
            "governed-repair-time-outside-jcs-safe-integer-domain"
        );
    }
}
