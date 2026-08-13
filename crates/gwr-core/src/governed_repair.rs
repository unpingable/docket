//! Pure contract for Docket-custodied governed-repair outcomes.
//!
//! This domain is deliberately separate from the retired campaign-stage
//! `exact_repair` office.  A governed-repair outcome is a terminal fact about
//! one already-custodied canonical AG issuance.  It grants no standing and is
//! never an instruction to continue execution.

use crate::digest::{Sha256Digest, Transcript};

pub const CANONICAL_EFFECT_SCOPE_SCHEMA_V1: &str = "ag.governed-loop.canonical-effect-scope/v1";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CanonicalEffectOperationV1 {
    Read,
    Create,
    Modify,
    Delete,
    Execute,
}

impl CanonicalEffectOperationV1 {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Create => "create",
            Self::Modify => "modify",
            Self::Delete => "delete",
            Self::Execute => "execute",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectResourceV1 {
    pub resource: String,
    pub path: String,
    pub operations: Vec<CanonicalEffectOperationV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalEffectScopeV1 {
    pub schema: String,
    pub effect_class: String,
    pub resources: Vec<EffectResourceV1>,
}

pub type RequestedEffectDeltaV1 = CanonicalEffectScopeV1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockedEffectV1 {
    pub effect_class: String,
    pub resource: String,
    pub path: String,
    pub operation: CanonicalEffectOperationV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedRepairBindingV1 {
    pub campaign: Sha256Digest,
    pub occurrence: String,
    pub proposal: Sha256Digest,
    pub observation: Sha256Digest,
    pub standing_resolution: Sha256Digest,
    pub decision: Sha256Digest,
    pub spend: Sha256Digest,
    pub issuance: Sha256Digest,
    pub custody: Sha256Digest,
    pub attempt: Sha256Digest,
    pub executor_result: Sha256Digest,
    pub executor_binding: Sha256Digest,
    pub original_scope: CanonicalEffectScopeV1,
    pub original_scope_digest: Sha256Digest,
    pub effect_journal_digest: Sha256Digest,
    pub authorized_effects_occurred: bool,
    pub created_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub idempotency: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeExpansionRequiredV1 {
    pub binding: GovernedRepairBindingV1,
    pub requested_delta: RequestedEffectDeltaV1,
    pub requested_delta_digest: Sha256Digest,
    pub blocked_effect: BlockedEffectV1,
    pub reason: Sha256Digest,
    pub dependency_evidence: Vec<Sha256Digest>,
    pub unauthorized_effect_not_performed: bool,
    pub limitations: Vec<Sha256Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadjudicationRequiredV1 {
    pub binding: GovernedRepairBindingV1,
    pub question: Sha256Digest,
    pub evidence_census: Vec<Sha256Digest>,
    pub diagnostic_census: Vec<Sha256Digest>,
    pub bounded_alternatives: Vec<Sha256Digest>,
    pub unresolved_facts: Vec<Sha256Digest>,
    pub adjudication_scope: CanonicalEffectScopeV1,
    pub unauthorized_effect_not_performed: bool,
    pub limitations: Vec<Sha256Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GovernedRepairRequirementV1 {
    ScopeExpansion(ScopeExpansionRequiredV1),
    Readjudication(ReadjudicationRequiredV1),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GovernedRepairRefusal {
    EmptyField,
    EmptyCollection,
    NonCanonicalCollection,
    ScopeDigestMismatch,
    DeltaDigestMismatch,
    DeltaAlreadyAuthorized,
    UnauthorizedEffectObserved,
    Expired,
    InvalidTimeWindow,
    BindingMismatch,
    ExactReplayCollision,
    AttemptAlreadyTerminal,
    LegacyAuthorityForbidden,
}

impl CanonicalEffectScopeV1 {
    pub fn validate(&self) -> Result<(), GovernedRepairRefusal> {
        if self.schema != CANONICAL_EFFECT_SCOPE_SCHEMA_V1
            || self.effect_class.is_empty()
            || self.resources.is_empty()
        {
            return Err(GovernedRepairRefusal::EmptyField);
        }
        let mut prior: Option<(&str, &str)> = None;
        for item in &self.resources {
            if !is_exact_label(&item.resource) || item.path.is_empty() || item.operations.is_empty()
            {
                return Err(GovernedRepairRefusal::EmptyField);
            }
            if !is_exact_relative_path(&item.path) {
                return Err(GovernedRepairRefusal::BindingMismatch);
            }
            if !strictly_sorted(item.operations.iter().copied()) {
                return Err(GovernedRepairRefusal::NonCanonicalCollection);
            }
            let key = (item.resource.as_str(), item.path.as_str());
            if prior.is_some_and(|previous| previous >= key) {
                return Err(GovernedRepairRefusal::NonCanonicalCollection);
            }
            prior = Some(key);
        }
        Ok(())
    }

    pub fn identity(&self) -> Result<Sha256Digest, GovernedRepairRefusal> {
        self.validate()?;
        let mut transcript = Transcript::new("ag.governed-loop.canonical-effect-scope/v1")
            .text_field("schema", &self.schema)
            .text_field("effect_class", &self.effect_class);
        for resource in &self.resources {
            transcript = transcript
                .text_field("resource", &resource.resource)
                .text_field("path", &resource.path);
            for operation in &resource.operations {
                transcript = transcript.text_field("operation", operation.tag());
            }
        }
        Ok(transcript.finalize())
    }

    pub fn overlaps(&self, delta: &RequestedEffectDeltaV1) -> bool {
        self.effect_class == delta.effect_class
            && delta.resources.iter().any(|requested| {
                self.resources.iter().any(|admitted| {
                    admitted.resource == requested.resource
                        && admitted.path == requested.path
                        && requested
                            .operations
                            .iter()
                            .any(|operation| admitted.operations.contains(operation))
                })
            })
    }
}

impl GovernedRepairRequirementV1 {
    pub fn binding(&self) -> &GovernedRepairBindingV1 {
        match self {
            Self::ScopeExpansion(value) => &value.binding,
            Self::Readjudication(value) => &value.binding,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::ScopeExpansion(_) => "scope_expansion_required",
            Self::Readjudication(_) => "readjudication_required",
        }
    }

    pub fn validate(&self, now_unix_ms: u64) -> Result<Sha256Digest, GovernedRepairRefusal> {
        let binding = self.binding();
        if binding.created_at_unix_ms > now_unix_ms || now_unix_ms >= binding.expires_at_unix_ms {
            return Err(GovernedRepairRefusal::Expired);
        }
        if binding.created_at_unix_ms >= binding.expires_at_unix_ms {
            return Err(GovernedRepairRefusal::InvalidTimeWindow);
        }
        // The upstream scope digest is AG's JCS-derived identity. Core validates
        // semantic shape while the Docket intake adapter verifies those exact
        // upstream bytes; it must not substitute its transcript identity.
        binding.original_scope.validate()?;
        let transcript = match self {
            Self::ScopeExpansion(value) => {
                value.requested_delta.validate()?;
                // An exact delta is strictly additive. It cannot redundantly
                // carry even one operation already admitted by the immutable
                // original scope, because that would make the approved
                // expansion ambiguous under later set composition.
                if binding.original_scope.overlaps(&value.requested_delta) {
                    return Err(GovernedRepairRefusal::DeltaAlreadyAuthorized);
                }
                if value.requested_delta.effect_class != value.blocked_effect.effect_class
                    || !value.requested_delta.resources.iter().any(|resource| {
                        resource.resource == value.blocked_effect.resource
                            && resource.path == value.blocked_effect.path
                            && resource
                                .operations
                                .contains(&value.blocked_effect.operation)
                    })
                {
                    return Err(GovernedRepairRefusal::BindingMismatch);
                }
                if value.dependency_evidence.is_empty() || value.limitations.is_empty() {
                    return Err(GovernedRepairRefusal::EmptyCollection);
                }
                if !value.unauthorized_effect_not_performed {
                    return Err(GovernedRepairRefusal::UnauthorizedEffectObserved);
                }
                require_canonical_digests(&value.dependency_evidence)?;
                require_canonical_digests(&value.limitations)?;
                requirement_transcript(
                    "docket.governed-repair.scope-expansion-required/v1",
                    binding,
                )
                .field("requested_delta", value.requested_delta_digest.as_bytes())
                .text_field("blocked_effect_class", &value.blocked_effect.effect_class)
                .text_field("blocked_resource", &value.blocked_effect.resource)
                .text_field("blocked_path", &value.blocked_effect.path)
                .text_field("blocked_operation", value.blocked_effect.operation.tag())
                .field("reason", value.reason.as_bytes())
                .field(
                    "dependency_evidence",
                    &digest_list(&value.dependency_evidence),
                )
                .field("limitations", &digest_list(&value.limitations))
            }
            Self::Readjudication(value) => {
                value.adjudication_scope.validate()?;
                if value
                    .adjudication_scope
                    .resources
                    .iter()
                    .flat_map(|resource| resource.operations.iter())
                    .any(|operation| *operation != CanonicalEffectOperationV1::Read)
                {
                    return Err(GovernedRepairRefusal::BindingMismatch);
                }
                if value.evidence_census.is_empty()
                    || value.diagnostic_census.is_empty()
                    || value.bounded_alternatives.is_empty()
                    || value.unresolved_facts.is_empty()
                    || value.limitations.is_empty()
                {
                    return Err(GovernedRepairRefusal::EmptyCollection);
                }
                if !value.unauthorized_effect_not_performed {
                    return Err(GovernedRepairRefusal::UnauthorizedEffectObserved);
                }
                require_canonical_digests(&value.evidence_census)?;
                require_canonical_digests(&value.diagnostic_census)?;
                require_canonical_digests(&value.bounded_alternatives)?;
                require_canonical_digests(&value.unresolved_facts)?;
                require_canonical_digests(&value.limitations)?;
                requirement_transcript("docket.governed-repair.readjudication-required/v1", binding)
                    .field("question", value.question.as_bytes())
                    .field("evidence_census", &digest_list(&value.evidence_census))
                    .field("diagnostic_census", &digest_list(&value.diagnostic_census))
                    .field(
                        "bounded_alternatives",
                        &digest_list(&value.bounded_alternatives),
                    )
                    .field("unresolved_facts", &digest_list(&value.unresolved_facts))
                    .field(
                        "adjudication_scope",
                        value.adjudication_scope.identity()?.as_bytes(),
                    )
                    .field("limitations", &digest_list(&value.limitations))
            }
        };
        Ok(transcript.finalize())
    }
}

fn requirement_transcript(domain: &'static str, binding: &GovernedRepairBindingV1) -> Transcript {
    Transcript::new(domain)
        .field("campaign", binding.campaign.as_bytes())
        .text_field("occurrence", &binding.occurrence)
        .field("proposal", binding.proposal.as_bytes())
        .field("observation", binding.observation.as_bytes())
        .field(
            "standing_resolution",
            binding.standing_resolution.as_bytes(),
        )
        .field("decision", binding.decision.as_bytes())
        .field("spend", binding.spend.as_bytes())
        .field("issuance", binding.issuance.as_bytes())
        .field("custody", binding.custody.as_bytes())
        .field("attempt", binding.attempt.as_bytes())
        .field("executor_result", binding.executor_result.as_bytes())
        .field("executor_binding", binding.executor_binding.as_bytes())
        .field("original_scope", binding.original_scope_digest.as_bytes())
        .field("effect_journal", binding.effect_journal_digest.as_bytes())
        .text_field(
            "authorized_effects_occurred",
            if binding.authorized_effects_occurred {
                "true"
            } else {
                "false"
            },
        )
        .text_field(
            "created_at_unix_ms",
            &binding.created_at_unix_ms.to_string(),
        )
        .text_field(
            "expires_at_unix_ms",
            &binding.expires_at_unix_ms.to_string(),
        )
        .field("idempotency", binding.idempotency.as_bytes())
}

fn digest_list(values: &[Sha256Digest]) -> [u8; 32] {
    let mut transcript = Transcript::new("docket.governed-repair.digest-list/v1");
    for value in values {
        transcript = transcript.field("item", value.as_bytes());
    }
    *transcript.finalize().as_bytes()
}

fn strictly_sorted<T: Copy + Ord>(mut values: impl Iterator<Item = T>) -> bool {
    let Some(mut previous) = values.next() else {
        return false;
    };
    for value in values {
        if previous >= value {
            return false;
        }
        previous = value;
    }
    true
}

fn require_canonical_digests(values: &[Sha256Digest]) -> Result<(), GovernedRepairRefusal> {
    if values.is_empty() || !strictly_sorted(values.iter().map(Sha256Digest::as_bytes)) {
        return Err(GovernedRepairRefusal::NonCanonicalCollection);
    }
    Ok(())
}

fn is_exact_relative_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.ends_with('/')
        && !path.contains('\\')
        && !path.chars().any(|character| {
            matches!(
                character,
                '*' | '?' | '[' | ']' | '{' | '}' | '!' | '$' | '`' | ';' | '|' | '&'
            )
        })
        && !path.bytes().any(|byte| byte.is_ascii_control())
        && path.split('/').all(|part| !matches!(part, "" | "." | ".."))
}

fn is_exact_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 128
        && label.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
        })
        && !["branch", "head", "ref"]
            .iter()
            .any(|word| label.to_ascii_lowercase().contains(word))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn scope() -> CanonicalEffectScopeV1 {
        CanonicalEffectScopeV1 {
            schema: CANONICAL_EFFECT_SCOPE_SCHEMA_V1.to_owned(),
            effect_class: "repository-write/v1".to_owned(),
            resources: vec![EffectResourceV1 {
                resource: "nq".to_owned(),
                path: "crates/nq-store/src/lib.rs".to_owned(),
                operations: vec![CanonicalEffectOperationV1::Modify],
            }],
        }
    }

    fn binding() -> GovernedRepairBindingV1 {
        let original_scope = scope();
        let original_scope_digest = original_scope.identity().unwrap();
        GovernedRepairBindingV1 {
            campaign: digest(2),
            occurrence: "00000000-0000-0000-0000-000000000001".to_owned(),
            proposal: digest(3),
            observation: digest(4),
            standing_resolution: digest(5),
            decision: digest(6),
            spend: digest(7),
            issuance: digest(8),
            custody: digest(9),
            attempt: digest(10),
            executor_result: digest(11),
            executor_binding: digest(12),
            original_scope,
            original_scope_digest,
            effect_journal_digest: digest(13),
            authorized_effects_occurred: true,
            created_at_unix_ms: 10,
            expires_at_unix_ms: 100,
            idempotency: digest(14),
        }
    }

    #[test]
    fn scope_expansion_must_name_an_effect_outside_frozen_scope() {
        let delta = CanonicalEffectScopeV1 {
            schema: CANONICAL_EFFECT_SCOPE_SCHEMA_V1.to_owned(),
            effect_class: "repository-write/v1".to_owned(),
            resources: vec![EffectResourceV1 {
                resource: "nq".to_owned(),
                path: "crates/nq-store/src/new.rs".to_owned(),
                operations: vec![CanonicalEffectOperationV1::Modify],
            }],
        };
        let requirement = GovernedRepairRequirementV1::ScopeExpansion(ScopeExpansionRequiredV1 {
            binding: binding(),
            requested_delta_digest: digest(17),
            requested_delta: delta,
            blocked_effect: BlockedEffectV1 {
                effect_class: "repository-write/v1".to_owned(),
                resource: "nq".to_owned(),
                path: "crates/nq-store/src/new.rs".to_owned(),
                operation: CanonicalEffectOperationV1::Modify,
            },
            reason: digest(18),
            dependency_evidence: vec![digest(15)],
            unauthorized_effect_not_performed: true,
            limitations: vec![digest(19)],
        });
        assert!(requirement.validate(20).is_ok());
    }

    #[test]
    fn already_authorized_delta_and_non_read_adjudication_scope_refuse() {
        let delta = scope();
        let expansion = GovernedRepairRequirementV1::ScopeExpansion(ScopeExpansionRequiredV1 {
            binding: binding(),
            requested_delta_digest: digest(17),
            requested_delta: delta,
            blocked_effect: BlockedEffectV1 {
                effect_class: "repository-write/v1".to_owned(),
                resource: "nq".to_owned(),
                path: "crates/nq-store/src/lib.rs".to_owned(),
                operation: CanonicalEffectOperationV1::Modify,
            },
            reason: digest(18),
            dependency_evidence: vec![digest(15)],
            unauthorized_effect_not_performed: true,
            limitations: vec![digest(19)],
        });
        assert_eq!(
            expansion.validate(20),
            Err(GovernedRepairRefusal::DeltaAlreadyAuthorized)
        );

        let readjudication =
            GovernedRepairRequirementV1::Readjudication(ReadjudicationRequiredV1 {
                binding: binding(),
                question: digest(20),
                evidence_census: vec![digest(15)],
                diagnostic_census: vec![digest(16)],
                bounded_alternatives: vec![digest(21)],
                unresolved_facts: vec![digest(22)],
                adjudication_scope: scope(),
                unauthorized_effect_not_performed: true,
                limitations: vec![digest(23)],
            });
        assert_eq!(
            readjudication.validate(20),
            Err(GovernedRepairRefusal::BindingMismatch)
        );
    }

    #[test]
    fn partially_overlapping_delta_refuses_instead_of_laundering_old_authority() {
        let delta = CanonicalEffectScopeV1 {
            schema: CANONICAL_EFFECT_SCOPE_SCHEMA_V1.to_owned(),
            effect_class: "repository-write/v1".to_owned(),
            resources: vec![EffectResourceV1 {
                resource: "nq".to_owned(),
                path: "crates/nq-store/src/lib.rs".to_owned(),
                operations: vec![
                    CanonicalEffectOperationV1::Modify,
                    CanonicalEffectOperationV1::Delete,
                ],
            }],
        };
        let expansion = GovernedRepairRequirementV1::ScopeExpansion(ScopeExpansionRequiredV1 {
            binding: binding(),
            requested_delta_digest: digest(17),
            requested_delta: delta,
            blocked_effect: BlockedEffectV1 {
                effect_class: "repository-write/v1".to_owned(),
                resource: "nq".to_owned(),
                path: "crates/nq-store/src/lib.rs".to_owned(),
                operation: CanonicalEffectOperationV1::Delete,
            },
            reason: digest(18),
            dependency_evidence: vec![digest(15)],
            unauthorized_effect_not_performed: true,
            limitations: vec![digest(19)],
        });
        assert_eq!(
            expansion.validate(20),
            Err(GovernedRepairRefusal::DeltaAlreadyAuthorized)
        );

        let mut strictly_additive = expansion;
        let GovernedRepairRequirementV1::ScopeExpansion(value) = &mut strictly_additive else {
            unreachable!()
        };
        value.requested_delta.resources[0].operations = vec![CanonicalEffectOperationV1::Delete];
        assert!(strictly_additive.validate(20).is_ok());
    }

    #[test]
    fn exact_paths_accept_unicode_and_spaces_but_refuse_ambient_coordinates() {
        let mut value = scope();
        value.resources[0].path = "docs/design notes/契約.md".to_owned();
        assert!(value.validate().is_ok());

        for path in [
            "/absolute",
            "../escape",
            "a/../escape",
            "a\\windows",
            "a/*",
            "a/",
        ] {
            value.resources[0].path = path.to_owned();
            assert_eq!(
                value.validate(),
                Err(GovernedRepairRefusal::BindingMismatch),
                "{path} must not be admitted"
            );
        }
        value.resources[0].path = "valid/path".to_owned();
        for resource in ["branch", "refs/heads/main", "HEAD"] {
            value.resources[0].resource = resource.to_owned();
            assert_eq!(value.validate(), Err(GovernedRepairRefusal::EmptyField));
        }
    }
}
