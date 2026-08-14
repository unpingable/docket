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
