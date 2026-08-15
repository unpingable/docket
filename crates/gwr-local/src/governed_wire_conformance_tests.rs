//! Ordinary-gate tests for Docket's complete AG-produced wire corpus.

use super::*;
use crate::governed_repair::{
    ag_custody_reference, validate_effect_journal_for_issuance, validate_read_result,
    EffectJournalEntryWireV1, StoreSealedGovernedRepairResultV1,
};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;

const WIRE_VECTORS: &[u8] =
    include_bytes!("../../../conformance/governed-repair-r2/wire-vectors.v1.json");
const WIRE_HOSTILES: &[u8] =
    include_bytes!("../../../conformance/governed-repair-r2/wire-hostiles.v1.json");
const RECONCILIATION_ROUNDS: &[u8] =
    include_bytes!("../../../conformance/governed-repair-r2/reconciliation-rounds.v1.json");

fn corpus() -> Value {
    strict_json(WIRE_VECTORS, "wire-vector-corpus").expect("pinned wire-vector corpus")
}

fn canonical_body(vector: &Value) -> &str {
    vector["canonical"]
        .as_str()
        .expect("canonical vector bytes")
}

fn round_trip<T>(vector: &Value, label: &str) -> T
where
    T: DeserializeOwned + Serialize,
{
    let typed: T = strict_json(canonical_body(vector).as_bytes(), label)
        .expect("actual Docket strict parser accepts the exact vector");
    assert_eq!(
        serde_jcs::to_vec(&typed).unwrap(),
        canonical_body(vector).as_bytes(),
        "Docket consumer spelling drifted from the AG-owned exact corpus"
    );
    typed
}

fn identity<'a>(vector: &'a Value, name: &str) -> &'a str {
    vector["identities"][name]
        .as_str()
        .expect("expected identity")
}

fn reconciliation_corpus() -> Value {
    strict_json(RECONCILIATION_ROUNDS, "reconciliation-round-corpus")
        .expect("pinned reconciliation-round corpus")
}

fn validate_corpus_round_response(
    response: &DocketReconciliationRoundResponseWireV1,
) -> Result<(), String> {
    if response.schema != RECONCILIATION_ROUND_RESPONSE_SCHEMA_V1 {
        return Err("corpus-reconciliation-response-schema".to_owned());
    }
    match &response.state {
        DocketReconciliationRoundStateWireV1::Unresolved(reservation) => {
            if reservation.request != response.request
                || reservation.round != response.round
                || reservation_identity(reservation)? != reservation.reservation
            {
                return Err("corpus-reconciliation-reservation-substitution".to_owned());
            }
        }
        DocketReconciliationRoundStateWireV1::Completed {
            reservation,
            completion,
            response: result,
        } => {
            if reservation.request != response.request
                || reservation.round != response.round
                || reservation_identity(reservation)? != reservation.reservation
                || completion.reservation != reservation.reservation
                || completion.round != reservation.round
                || completion_identity(completion)? != completion.completion
            {
                return Err("corpus-reconciliation-completed-substitution".to_owned());
            }
            let result_identity = match result.as_ref() {
                DocketReconciliationWireV1::Indeterminate { indeterminate, .. } => {
                    &indeterminate.reconciliation
                }
                DocketReconciliationWireV1::Settled { settlement, .. } => &settlement.settlement,
                DocketReconciliationWireV1::GovernedRepairRequired { result, .. } => {
                    &result.sealed_result
                }
                _ => return Err("corpus-reconciliation-completed-result-class".to_owned()),
            };
            if completion.result_identity != *result_identity {
                return Err("corpus-reconciliation-public-result-substitution".to_owned());
            }
        }
        DocketReconciliationRoundStateWireV1::NotAccepted
        | DocketReconciliationRoundStateWireV1::Refused(_) => {}
    }
    Ok(())
}

#[test]
fn reconciliation_round_corpus_exercises_actual_docket_types_and_identities() {
    let corpus = reconciliation_corpus();
    for name in [
        "reconciliation_request_initial",
        "reconciliation_request_later",
    ] {
        let vector = &corpus["records"][name];
        let request: ReconciliationRoundRequestWireV1 = round_trip(vector, name);
        validate_reconciliation_round_request(&request).unwrap();
        assert_eq!(request.round, identity(vector, "round"));
        assert_eq!(request.request, identity(vector, "request"));
    }
    let signed_vector = &corpus["records"]["signed_reconciliation_request_initial"];
    let signed: SignedReconciliationRoundRequestEnvelopeWireV1 =
        round_trip(signed_vector, "signed-reconciliation-request");
    let trust = serde_jcs::to_vec(&AgIssuerTrustConfigV1 {
        issuers: vec![TrustedAgIssuerV1 {
            issuer_principal: signed.authentication.issuer_principal.clone(),
            key_id: signed.authentication.signer_key_id.clone(),
            public_key: signed.authentication.signer_public_key.clone(),
        }],
    })
    .unwrap();
    let (_, request) = verify_signed_reconciliation_round_request(
        canonical_body(signed_vector).as_bytes(),
        &trust,
    )
    .unwrap();
    assert_eq!(
        request.request,
        identity(
            &corpus["records"]["reconciliation_request_initial"],
            "request"
        )
    );

    for name in [
        "reconciliation_reservation_initial",
        "reconciliation_reservation_later",
    ] {
        let vector = &corpus["records"][name];
        let reservation: ReconciliationRoundReservationWireV1 = round_trip(vector, name);
        assert_eq!(
            reservation_identity(&reservation).unwrap(),
            identity(vector, "reservation")
        );
    }
    for name in [
        "reconciliation_completion_indeterminate",
        "reconciliation_completion_settled",
    ] {
        let vector = &corpus["records"][name];
        let completion: ReconciliationRoundCompletionWireV1 = round_trip(vector, name);
        assert_eq!(
            completion_identity(&completion).unwrap(),
            identity(vector, "completion")
        );
    }
    for name in [
        "reconciliation_response_unresolved",
        "reconciliation_response_completed_indeterminate",
        "reconciliation_response_completed_settled",
    ] {
        let response: DocketReconciliationRoundResponseWireV1 =
            round_trip(&corpus["records"][name], name);
        validate_corpus_round_response(&response).unwrap();
    }
    let _: ExecutorReconciliationDispatchWireV1 = round_trip(
        &corpus["records"]["executor_reconciliation_dispatch"],
        "executor-reconciliation-dispatch",
    );
}

#[test]
fn actual_docket_intake_records_reproduce_all_positive_identities() {
    let corpus = corpus();
    for name in [
        "ag_issuance_checkpoint_diff_absent",
        "ag_issuance_checkpoint_diff_present",
    ] {
        let vector = &corpus["records"][name];
        let issuance: AgIssuanceWireV2 = round_trip(vector, name);
        validate_issuance(&issuance).unwrap();
        assert_eq!(
            ag_issuance_identity(&issuance).unwrap(),
            identity(vector, "issuance")
        );
        assert_eq!(issuance.effect_scope_digest, identity(vector, "scope"));
        assert_eq!(
            issuance
                .governed_repair_checkpoint
                .as_ref()
                .and_then(|checkpoint| checkpoint.diff_identity.as_deref())
                .is_some(),
            name.ends_with("present")
        );
    }

    let issuance: AgIssuanceWireV2 = round_trip(
        &corpus["records"]["ag_issuance_checkpoint_diff_absent"],
        "issuance",
    );
    let custody_vector = &corpus["records"]["docket_custody"];
    let custody: DocketCustodyWireV1 = round_trip(custody_vector, "custody");
    assert_eq!(
        ag_custody_reference(&custody).unwrap(),
        identity(custody_vector, "custody")
    );

    let journal_vector = &corpus["records"]["docket_effect_journal"];
    let journal: Vec<EffectJournalEntryWireV1> = round_trip(journal_vector, "effect-journal");
    assert_eq!(
        validate_effect_journal_for_issuance(&issuance.effect_scope, &journal).unwrap(),
        identity(journal_vector, "journal")
    );

    let settlement_vector = &corpus["records"]["docket_settlement"];
    let settlement: DocketSettlementWireV1 = round_trip(settlement_vector, "settlement");
    assert_eq!(
        docket_settlement_identity(&settlement).unwrap(),
        identity(settlement_vector, "settlement")
    );
    assert_eq!(
        settlement.cumulative_effect_journal_identity,
        identity(settlement_vector, "cumulative_effect_journal")
    );

    let indeterminate_vector = &corpus["records"]["docket_indeterminate"];
    let indeterminate: IndeterminateOutcomeWireV1 =
        round_trip(indeterminate_vector, "indeterminate");
    assert_eq!(
        hash_domain(
            "docket.governed-loop.reconciliation/v1",
            format!(
                "{}:{}:{}",
                indeterminate.issuance, indeterminate.attempt, indeterminate.evidence
            )
            .as_bytes(),
        ),
        identity(indeterminate_vector, "reconciliation")
    );

    for vector in corpus["refusals"].as_array().unwrap() {
        let refusal: DocketIssuanceRefusalWireV1 = round_trip(vector, "issuance-refusal");
        assert_eq!(
            refusal_identity(&refusal).unwrap(),
            identity(vector, "refusal")
        );
    }
}

#[test]
fn actual_docket_closed_response_and_reconciliation_variants_round_trip() {
    let corpus = corpus();
    for vector in corpus["acceptance_variants"].as_object().unwrap().values() {
        let _: DocketExecutionResponseWireV1 = round_trip(vector, "execution-response");
    }
    for vector in corpus["reconciliation_variants"]
        .as_object()
        .unwrap()
        .values()
    {
        let _: DocketReconciliationWireV1 = round_trip(vector, "reconciliation-response");
    }
}

#[test]
fn actual_docket_result_validator_reproduces_both_governed_families() {
    let corpus = corpus();
    let issuance: AgIssuanceWireV2 = round_trip(
        &corpus["records"]["ag_issuance_checkpoint_diff_absent"],
        "issuance",
    );
    let journal: Vec<EffectJournalEntryWireV1> = round_trip(
        &corpus["records"]["docket_effect_journal"],
        "effect-journal",
    );
    for name in [
        "governed_scope_expansion_result",
        "governed_readjudication_result",
    ] {
        let vector = &corpus["records"][name];
        let result: StoreSealedGovernedRepairResultV1 = round_trip(vector, name);
        validate_read_result(&result, &issuance, &journal)
            .expect("the exact result passes Docket's production replay validator");
        assert_eq!(
            result.checkpoint.requirement_identity,
            identity(vector, "requirement_identity")
        );
        assert_eq!(
            result.checkpoint.checkpoint,
            identity(vector, "checkpoint_identity")
        );
        assert_eq!(
            result.sealed_result,
            identity(vector, "sealed_result_identity")
        );
    }
}

fn base_value<'a>(corpus: &'a Value, name: &str) -> &'a Value {
    &corpus["records"][name]["value"]
}

fn mutate(mut value: Value, pointer: &str, replacement: Value) -> Value {
    let (parent, member) = pointer.rsplit_once('/').expect("non-root pointer");
    let target = value
        .pointer_mut(parent)
        .expect("hostile pointer names an exact vector member");
    if let Some(object) = target.as_object_mut() {
        object.insert(member.to_owned(), replacement);
    } else if let Some(array) = target.as_array_mut() {
        array[member.parse::<usize>().unwrap()] = replacement;
    } else {
        panic!("hostile pointer parent is neither object nor array");
    }
    value
}

fn strict_decode<T: DeserializeOwned>(value: &Value, label: &str) -> Result<T, String> {
    strict_json(&serde_json::to_vec(value).unwrap(), label)
}

#[test]
fn hostile_optional_unknown_integer_and_identity_mutations_refuse_in_docket() {
    let corpus = corpus();
    let hostiles: Value = strict_json(WIRE_HOSTILES, "wire-hostile-corpus").unwrap();
    let issuance: AgIssuanceWireV2 = round_trip(
        &corpus["records"]["ag_issuance_checkpoint_diff_absent"],
        "issuance",
    );
    let journal: Vec<EffectJournalEntryWireV1> = round_trip(
        &corpus["records"]["docket_effect_journal"],
        "effect-journal",
    );
    for case in hostiles["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let base = case["base"].as_str().unwrap();
        let replacement = if case["value_encoding"] == "json_integer_decimal" {
            serde_json::from_str::<Value>(case["value"].as_str().unwrap()).unwrap()
        } else {
            case["value"].clone()
        };
        let mutated = mutate(
            base_value(&corpus, base).clone(),
            case["pointer"].as_str().unwrap(),
            replacement,
        );
        let result = match base {
            "ag_issuance_checkpoint_diff_absent" => {
                strict_decode::<AgIssuanceWireV2>(&mutated, name).and_then(|value| {
                    validate_issuance(&value)?;
                    if ag_issuance_identity(&value)? == value.issuance {
                        Ok(())
                    } else {
                        Err("governed-issuance-identity-substitution".to_owned())
                    }
                })
            }
            "docket_settlement" => strict_decode::<DocketSettlementWireV1>(&mutated, name)
                .and_then(|value| {
                    if docket_settlement_identity(&value)? == value.settlement {
                        Ok(())
                    } else {
                        Err("governed-settlement-identity-substitution".to_owned())
                    }
                }),
            "governed_scope_expansion_result" => {
                strict_decode::<StoreSealedGovernedRepairResultV1>(&mutated, name)
                    .and_then(|value| validate_read_result(&value, &issuance, &journal))
            }
            _ => panic!("hostile corpus names unknown base {base}"),
        };
        assert!(
            result.is_err(),
            "hostile case passed Docket boundary: {name}"
        );
    }
}

fn apply_reconciliation_hostile(base: Value, case: &Value) -> Value {
    let pointer = case["pointer"].as_str().unwrap();
    let (parent, member) = pointer.rsplit_once('/').expect("non-root pointer");
    let mut value = base;
    let target = value
        .pointer_mut(parent)
        .expect("round hostile pointer names an exact member");
    let object = target
        .as_object_mut()
        .expect("round hostile pointer parent is an object");
    match case["operation"].as_str().unwrap() {
        "remove" => {
            object.remove(member).expect("member to remove");
        }
        "add" | "replace" => {
            let replacement = if case["value_encoding"] == "json_integer_decimal" {
                serde_json::from_str(case["value"].as_str().unwrap()).unwrap()
            } else {
                case["value"].clone()
            };
            object.insert(member.to_owned(), replacement);
        }
        operation => panic!("unknown round hostile operation {operation}"),
    }
    value
}

#[test]
fn reconciliation_round_hostiles_owned_by_docket_refuse_at_their_exact_boundary() {
    let corpus = reconciliation_corpus();
    let signed: SignedReconciliationRoundRequestEnvelopeWireV1 = round_trip(
        &corpus["records"]["signed_reconciliation_request_initial"],
        "signed-reconciliation-request",
    );
    let trust = serde_jcs::to_vec(&AgIssuerTrustConfigV1 {
        issuers: vec![TrustedAgIssuerV1 {
            issuer_principal: signed.authentication.issuer_principal,
            key_id: signed.authentication.signer_key_id,
            public_key: signed.authentication.signer_public_key,
        }],
    })
    .unwrap();
    for case in corpus["hostiles"].as_array().unwrap() {
        // Complete-envelope replay at the executor is intentionally owned by
        // ag-effectd. Docket's positive corpus test proves it emits the exact
        // base wrapper; AG's mirrored ordinary gate exercises those two
        // executor-owned mutations against the actual adapter.
        if case["refusal_owner"] == "executor-exact-replay" {
            continue;
        }
        let name = case["name"].as_str().unwrap();
        let base = case["base"].as_str().unwrap();
        let mutated = apply_reconciliation_hostile(corpus["records"][base]["value"].clone(), case);
        let bytes = serde_jcs::to_vec(&mutated).unwrap();
        let result = match base {
            "reconciliation_request_initial" | "reconciliation_request_later" => {
                strict_json::<ReconciliationRoundRequestWireV1>(&bytes, name)
                    .and_then(|request| validate_reconciliation_round_request(&request))
            }
            "signed_reconciliation_request_initial" => {
                verify_signed_reconciliation_round_request(&bytes, &trust).map(|_| ())
            }
            "reconciliation_response_unresolved"
            | "reconciliation_response_completed_indeterminate" => {
                strict_json::<DocketReconciliationRoundResponseWireV1>(&bytes, name)
                    .and_then(|response| validate_corpus_round_response(&response))
            }
            "executor_reconciliation_dispatch" => {
                strict_json::<ExecutorReconciliationDispatchWireV1>(&bytes, name).map(|_| ())
            }
            other => panic!("unknown Docket-owned reconciliation hostile base {other}"),
        };
        assert!(
            result.is_err(),
            "round hostile passed Docket boundary: {name}"
        );
    }
}
