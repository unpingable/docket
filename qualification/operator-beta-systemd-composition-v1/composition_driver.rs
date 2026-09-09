//! Qualification-only AG -> Docket -> ag-effectd systemd composition driver.
//!
//! This source is compiled against exact, externally pinned AG and Docket
//! owners for the bounded operator-beta fixture. It is not a product runtime,
//! service, alternate authority path, or persistence owner.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use ag_app::effect_executor_adapter::{
    reconcile_systemd_effect_attempt, reopen_systemd_dbus_evidence, EffectExecutorDispatchV1,
    EffectExecutorSystemdPlanV2, EffectFilePolicyV1, EFFECT_EXECUTOR_SYSTEMD_PLAN_SCHEMA_V2,
    EFFECT_EXECUTOR_SYSTEMD_WORK_SCHEMA_V2,
};
use ag_app::governed_loop::{
    CampaignEngineV1, DocketProgressV1, ExactWorkCatalogEntryV1, ExactWorkCatalogV1,
    WorkPreconditionV1, EXACT_WORK_CATALOG_SCHEMA_V1,
};
use ag_app::governed_ports::{AgIssuanceSignerV1, CommandDocketCustodyPortV1};
use ag_campaign::governed::*;
use ag_campaign::CampaignId;
use ag_effect::{CanonicalEffectV1, SystemdUnitActionV1, TargetId};
use ag_primitives::{Digest, JcsDocument};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use serde::Serialize;
use serde_json::{json, Value};
use uuid::Uuid;

const OBSERVATION_RESOLVER_ID: &str = "operator-beta.composition-observation/v1";
const STANDING_RESOLVER_ID: &str = "operator-beta.composition-standing/v1";
const ISSUER_PRINCIPAL: &str = "constellation-operator-beta-ag";
const ISSUER_KEY_ID: &str = "operator-beta-composition-key-1";
#[cfg(feature = "m3-labelwatch")]
const FIXTURE_TARGET: &str = "labelwatch-sqlite-maintenance";
#[cfg(not(feature = "m3-labelwatch"))]
const FIXTURE_TARGET: &str = "constellation-beta-http-fixture";

fn digest(label: &str) -> Digest {
    Digest::hash_domain(
        "constellation/operator-beta/docket-systemd-composition/v1",
        label.as_bytes(),
    )
}

fn clean_basis() -> DecisionBasisV1 {
    DecisionBasisV1 {
        schema: DECISION_BASIS_SCHEMA_V1.to_owned(),
        rule: DecisionBasisRuleV1 {
            id: DECISION_BASIS_RULE_ID_V1.to_owned(),
            version: DECISION_BASIS_RULE_VERSION_V1.to_owned(),
            digest: decision_basis_rule_digest_v1().as_str().to_owned(),
        },
        atoms: BTreeSet::from([
            "condition.clean".to_owned(),
            "delivery.not_required".to_owned(),
        ]),
    }
}

struct Observation;

impl ObservationResolverV1 for Observation {
    fn resolve_observation(
        &mut self,
        request: &ObservationResolutionRequestV1<'_>,
    ) -> Result<VersionedObservationResolutionV1, ExternalBoundaryErrorV1> {
        let basis = clean_basis();
        Ok(ObservationResolutionV2 {
            schema: OBSERVATION_RESOLUTION_SCHEMA_V2.to_owned(),
            key: request.key.clone(),
            observation: request.observation.clone(),
            currentness: ObservationCurrentnessRefV1::from_digest(digest("observation-current")),
            normalized_preconditions: PreconditionBasisRefV1::from_digest(
                basis
                    .decision_basis_digest()
                    .map_err(|_| ExternalBoundaryErrorV1::Refused {
                        code: "composition-basis".to_owned(),
                        evidence: None,
                    })?,
            ),
            basis,
            resolver_id: OBSERVATION_RESOLVER_ID.to_owned(),
            subject: request.subject.clone(),
            status: ObservationStatusV1::Current,
            resolved_at_unix_ms: request.now_unix_ms,
            fresh_until_unix_ms: request.now_unix_ms + 60_000,
        }
        .into())
    }
}

struct Standing { expires_at: Option<u64> }

impl StandingResolverV1 for Standing {
    fn resolve_standing(
        &mut self,
        request: &StandingResolutionRequestV1<'_>,
    ) -> Result<CurrentStandingResolutionV2, ExternalBoundaryErrorV1> {
        Ok(CurrentStandingResolutionV2 {
            schema: STANDING_RESOLUTION_SCHEMA_V2.to_owned(),
            resolution: StandingResolutionRefV1::from_digest(digest("ag-standing-resolution")),
            currentness: StandingCurrentnessRefV1::from_digest(digest("ag-standing-current")),
            mandate: MandateRefV1::from_digest(digest("operator-beta-mandate")),
            key: request.key.clone(),
            observation: request.observation.clone(),
            proposal: request.proposal.clone(),
            subject: request.subject.clone(),
            scope: request.scope.clone(),
            resolver_id: STANDING_RESOLVER_ID.to_owned(),
            status: StandingStatusV1::Current,
            resolved_at_unix_ms: request.now_unix_ms,
            expires_at_unix_ms: self.expires_at.unwrap_or(request.now_unix_ms + 60_000),
        })
    }
}

pub(crate) struct Scenario {
    root: PathBuf,
    database: PathBuf,
    plan_path: PathBuf,
    plan: EffectExecutorSystemdPlanV2,
    work: Digest,
    pub(crate) subject: Digest,
    pub(crate) scope: Digest,
    campaign: CampaignId,
}

impl Scenario {
    fn create(
        root: PathBuf,
        run_id: &str,
        machine_id: String,
        unit: String,
        subject: Digest,
        scope: Digest,
    ) -> Result<Self, String> {
        std::fs::create_dir(&root).map_err(|error| error.to_string())?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
        let plan = EffectExecutorSystemdPlanV2 {
            schema: EFFECT_EXECUTOR_SYSTEMD_PLAN_SCHEMA_V2.to_owned(),
            attempt_store: root.join("ag-effectd-attempts.sqlite"),
            subject: subject.clone(),
            scope: scope.clone(),
            effect_index: 0,
            effect: CanonicalEffectV1::SystemdUnit {
                target: TargetId::parse(FIXTURE_TARGET)
                    .map_err(|error| error.to_string())?,
                unit,
                action: SystemdUnitActionV1::Start,
                expected_active_state: "inactive".to_owned(),
                expected_unit_file_state: "disabled".to_owned(),
            },
            file_policy: EffectFilePolicyV1 {
                max_content_bytes: 1024,
                trusted_ancestor_uid: 0,
                trusted_parent_uid: 0,
                require_private_parent_writes: true,
            },
            systemd_machine_identity: machine_id,
            execution_lock_timeout_ms: 5_000,
            job_timeout_ms: 30_000,
        };
        let work = plan.identity()?;
        let plan_path = root.join("systemd-plan-v2.json");
        write_canonical(&plan_path, &plan)?;
        Ok(Self {
            database: root.join("ag-campaign.sqlite"),
            plan_path,
            plan,
            work,
            subject,
            scope,
            campaign: CampaignId::from_digest(digest(&format!("campaign:{run_id}"))),
            root,
        })
    }

    fn engine(&self) -> Result<CampaignEngineV1, String> {
        CampaignEngineV1::create(
            &self.database,
            self.campaign.clone(),
            OccurrenceId::from_uuid(Uuid::from_u128(1)),
            ProgramBasisRefV1::from_digest(digest("operator-beta-program")),
            self.work.clone(),
            ResidualSetV1::default(),
            LoopBudgetV1 {
                retry_limit: 1,
                retries_used: 0,
                probe_limit: 1,
                probes_used: 0,
                escalation_limit: 1,
                escalations_used: 0,
            },
            1,
        )
        .map_err(|error| error.to_string())
    }

    pub(crate) fn proposal(&self) -> Result<ExactWorkProposalV1, String> {
        ExactWorkProposalV1::new(
            self.campaign.clone(),
            self.subject.clone(),
            self.scope.clone(),
            EFFECT_EXECUTOR_SYSTEMD_WORK_SCHEMA_V2.to_owned(),
            self.work.clone(),
            None,
        )
        .map_err(|error| error.to_string())
    }

    pub(crate) fn catalog(&self) -> ExactWorkCatalogV1 {
        ExactWorkCatalogV1 {
            schema: EXACT_WORK_CATALOG_SCHEMA_V1.to_owned(),
            entries: BTreeMap::from([(
                EFFECT_EXECUTOR_SYSTEMD_WORK_SCHEMA_V2.to_owned(),
                ExactWorkCatalogEntryV1 {
                    work_schema: EFFECT_EXECUTOR_SYSTEMD_WORK_SCHEMA_V2.to_owned(),
                    subject: self.subject.clone(),
                    scope: self.scope.clone(),
                    precondition: WorkPreconditionV1::default(),
                },
            )]),
        }
    }
}

struct DocketFiles {
    state: PathBuf,
    trust: PathBuf,
    resolver: PathBuf,
    signer: AgIssuanceSignerV1,
}

fn docket_files(root: &Path, execution_boundary: Option<&ExecutionBoundary>, issuance: &AgIssuanceV1) -> Result<DocketFiles, String> {
    let key_document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| "could not generate qualification Ed25519 key".to_owned())?;
    let pair = Ed25519KeyPair::from_pkcs8(key_document.as_ref())
        .map_err(|_| "could not parse qualification Ed25519 key".to_owned())?;
    let signer =
        AgIssuanceSignerV1::from_pkcs8(ISSUER_PRINCIPAL, ISSUER_KEY_ID, key_document.as_ref())
            .map_err(|error| error.to_string())?;
    let trust = root.join("docket-trust.json");
    write_canonical(
        &trust,
        &json!({"issuers":[{
            "issuer_principal": ISSUER_PRINCIPAL,
            "key_id": ISSUER_KEY_ID,
            "public_key": URL_SAFE_NO_PAD.encode(pair.public_key().as_ref())
        }]}),
    )?;
    let resolver = root.join("docket-standing-resolver");
    let mut resolver_source = r#"#!/usr/bin/python3
import hashlib,json,sys
r=json.load(sys.stdin); i=r["issuance"]
def d(label): return "sha256:"+hashlib.sha256(label.encode()).hexdigest()
o={"schema":"docket.governed-loop.execution-standing-resolution/v1","resolution":d("operator-beta-resolution"),"currentness":d("operator-beta-currentness"),"execution_standing":d("operator-beta-execution-standing"),"issuance":i["issuance"],"campaign":i["key"]["campaign"],"occurrence":i["key"]["occurrence"],"subject":i["subject"],"scope":i["scope"],"status":"current","resolved_at_unix_ms":r["now_unix_ms"],"expires_at_unix_ms":r["now_unix_ms"]+60000}
sys.stdout.write(json.dumps(o,sort_keys=True,separators=(",",":")))
"#.to_owned();
    if let Some(boundary) = execution_boundary {
        let encoded = serde_json::to_string(&serde_json::to_string(issuance).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
        let guard = format!("\nif i != json.loads({encoded}): raise SystemExit('exact enrolled issuance differs')\no['expires_at_unix_ms']={}\nif r['now_unix_ms'] >= {}: o['status']='expired'\n", boundary.expires_at, boundary.expires_at);
        resolver_source = resolver_source.replace("sys.stdout.write", &(guard + "sys.stdout.write"));
    }
    std::fs::write(&resolver, resolver_source)
    .map_err(|error| error.to_string())?;
    std::fs::set_permissions(&resolver, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())?;
    Ok(DocketFiles {
        state: root.join("docket-state"),
        trust,
        resolver,
        signer,
    })
}

pub(crate) fn authorize(engine: &mut CampaignEngineV1, scenario: &Scenario) -> Result<(), String> {
    let mut observation = Observation;
    let mut tick = 1;
    authorize_with_observation(engine, scenario, &mut observation,
        ObservationRefV1::from_digest(digest("observation")), OBSERVATION_RESOLVER_ID,
        || { tick += 1; tick }, None)
}

pub(crate) fn authorize_with_observation<O: ObservationResolverV1>(
    engine: &mut CampaignEngineV1,
    scenario: &Scenario,
    observation: &mut O,
    reference: ObservationRefV1,
    resolver_id: &str,
    mut now: impl FnMut() -> u64,
    expires_at: Option<u64>,
) -> Result<(), String> {
    let mut standing = Standing { expires_at };
    engine
        .record_proposal(
            reference,
            scenario.proposal()?,
            ProposalClassV1::Initial,
            observation,
            resolver_id,
            now(),
        )
        .map_err(|error| error.to_string())?;
    engine
        .require_standing(now())
        .map_err(|error| error.to_string())?;
    engine
        .decide(
            observation,
            &mut standing,
            &scenario.catalog(),
            None,
            resolver_id,
            STANDING_RESOLVER_ID,
            60_000,
            now(),
        )
        .map_err(|error| error.to_string())?;
    engine
        .authorize(
            observation,
            &mut standing,
            &scenario.catalog(),
            None,
            resolver_id,
            STANDING_RESOLVER_ID,
            60_000,
            now(),
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn inspect_docket(docket: &Path, state: &Path, issuance: &str) -> Result<(Value, Vec<u8>), String> {
    let output = Command::new(docket)
        .args([
            "governed-loop",
            "inspect",
            "--state",
            state.to_str().ok_or("Docket state path is not UTF-8")?,
            "--issuance",
            issuance,
        ])
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    let inspection = serde_json::from_slice(&output.stdout).map_err(|error| error.to_string())?;
    Ok((inspection, output.stdout))
}

fn require_absolute_executable(path: &Path, label: &str) -> Result<PathBuf, String> {
    let path = path
        .canonicalize()
        .map_err(|error| format!("{label}: {error}"))?;
    let metadata = std::fs::metadata(&path).map_err(|error| format!("{label}: {error}"))?;
    if !path.is_absolute() || !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(format!(
            "{label} is not an absolute executable regular file"
        ));
    }
    Ok(path)
}

fn write_canonical<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let document = JcsDocument::canonicalize(value).map_err(|error| error.to_string())?;
    let mut bytes = document.as_bytes().to_vec();
    bytes.push(b'\n');
    std::fs::write(path, bytes).map_err(|error| error.to_string())
}

#[cfg(not(feature = "m3-labelwatch"))]
fn main() {
    if let Err(error) = run() {
        eprintln!("operator-beta composition refused: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(feature = "m3-labelwatch"))]
fn run() -> Result<(), String> {
    let mut tick = 5;
    run_with_admission(std::env::args().skip(1), authorize, || { tick += 1; tick }, None)
}

pub(crate) struct ExecutionBoundary {
    pub expires_at: u64,
    pub observation: ObservationRefV1,
}

/// A bounded qualification seam: reuse the exact custody/replay path while a
/// companion supplies its factual admission resolver and clock. Not a router.
pub(crate) fn run_with_admission(
    mut args: impl Iterator<Item = String>,
    admit: impl FnOnce(&mut CampaignEngineV1, &Scenario) -> Result<(), String>,
    mut now: impl FnMut() -> u64,
    execution_boundary: Option<ExecutionBoundary>,
) -> Result<(), String> {
    let docket = require_absolute_executable(
        &PathBuf::from(args.next().ok_or(
            "usage: composition_driver DOCKET AG_EFFECTD OUTPUT RUN_ID MACHINE_ID UNIT SUBJECT SCOPE",
        )?),
        "Docket binary",
    )?;
    let effectd = require_absolute_executable(
        &PathBuf::from(args.next().ok_or("missing ag-effectd binary")?),
        "ag-effectd binary",
    )?;
    let output = PathBuf::from(args.next().ok_or("missing output path")?);
    let run_id = args.next().ok_or("missing run identity")?;
    let machine_id = args.next().ok_or("missing machine identity")?;
    let unit = args.next().ok_or("missing systemd unit")?;
    let subject = Digest::parse(&args.next().ok_or("missing subject identity")?)
        .map_err(|error| error.to_string())?;
    let scope = Digest::parse(&args.next().ok_or("missing scope identity")?)
        .map_err(|error| error.to_string())?;
    if args.next().is_some()
        || !output.is_absolute()
        || output.exists()
        || run_id.is_empty()
        || run_id.len() > 128
    {
        return Err("invalid bounded composition invocation".to_owned());
    }

    std::fs::create_dir(&output).map_err(|error| error.to_string())?;
    std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())?;
    let scenario = Scenario::create(
        output.join("occurrence"),
        &run_id,
        machine_id,
        unit,
        subject,
        scope,
    )?;
    let mut engine = scenario.engine()?;
    if let Err(error) = admit(&mut engine, &scenario) {
        #[cfg(feature = "m3-labelwatch")]
        {
            write_canonical(&output.join("admission-refusal-state.json"), &engine.current().map_err(|e| e.to_string())?)?;
            write_canonical(&output.join("admission-refusal-replay.json"), &engine.replay().map_err(|e| e.to_string())?)?;
            write_canonical(&output.join("admission-refusal-history.json"), &engine.history().map_err(|e| e.to_string())?)?;
        }
        return Err(error);
    }
    let authorization_state = engine.current().map_err(|error| error.to_string())?;
    let issuance = authorization_state
        .issuance()
        .cloned()
        .ok_or("authorization did not retain an issuance")?;
    if let Some(boundary) = &execution_boundary {
        if now() >= boundary.expires_at || issuance.observation != boundary.observation {
            return Err("native prerequisite expired or issuance observation differs before dispatch".into());
        }
    }
    let files = docket_files(&scenario.root, execution_boundary.as_ref(), &issuance)?;
    let docket_state = files.state.clone();
    let mut custody_port = CommandDocketCustodyPortV1::new(
        &docket,
        &files.state,
        &files.trust,
        &files.resolver,
        &effectd,
        &scenario.plan_path,
        files.signer,
    );
    let dispatched = engine
        .dispatch(&mut custody_port, now())
        .map_err(|error| error.to_string())?;
    let custody = dispatched
        .docket_custody()
        .cloned()
        .ok_or("Docket did not return custody")?;
    let DocketProgressV1::Settled(settled) = engine
        .poll_docket(&mut custody_port, now())
        .map_err(|error| error.to_string())?
    else {
        return Err("composed occurrence did not reach a known settlement".to_owned());
    };
    let settlement = settled
        .settlement()
        .cloned()
        .ok_or("settled occurrence has no Docket settlement")?;

    use ag_campaign::governed::DocketCustodyPortV1 as _;
    let duplicate = custody_port
        .accept_issuance(&issuance)
        .map_err(|error| format!("duplicate issuance: {error:?}"))?;
    if duplicate != custody {
        return Err("identical issuance did not converge on retained Docket custody".to_owned());
    }
    #[cfg(feature = "m3-labelwatch")]
    write_canonical(&output.join("duplicate-custody.json"), &duplicate)?;
    let (inspection, inspection_raw) =
        inspect_docket(&docket, &docket_state, issuance.issuance.as_str())?;
    if inspection["record"]["status"] != "settled" {
        return Err("query-only Docket inspection did not reopen settlement".to_owned());
    }

    let dispatch = EffectExecutorDispatchV1 {
        attempt: custody.attempt.as_digest().clone(),
        marker: custody.executor_marker.as_digest().clone(),
        work_schema: EFFECT_EXECUTOR_SYSTEMD_WORK_SCHEMA_V2.to_owned(),
        work: scenario.work.clone(),
        subject: scenario.subject.clone(),
        scope: scenario.scope.clone(),
    };
    let executor_outcome = reconcile_systemd_effect_attempt(&scenario.plan, &dispatch)?;
    let systemd_evidence = reopen_systemd_dbus_evidence(&scenario.plan, &dispatch)?;
    if executor_outcome.receipt.as_str() != settlement.receipt.as_str() {
        return Err("executor receipt and Docket settlement receipt disagree".to_owned());
    }
    let replay = engine.replay().map_err(|error| error.to_string())?;
    if replay.ag_spends != 1 || replay.docket_attempts != 1 || replay.settlements != 1 {
        return Err("AG replay cardinality differs from one spend/attempt/settlement".to_owned());
    }
    drop(engine);
    let reopened = CampaignEngineV1::open(&scenario.database).map_err(|error| error.to_string())?;
    if reopened.current().map_err(|error| error.to_string())? != settled {
        return Err("AG restart did not reconstruct the exact settled state".to_owned());
    }

    write_canonical(
        &output.join("authorization-state.json"),
        &authorization_state,
    )?;
    write_canonical(&output.join("issuance.json"), &issuance)?;
    write_canonical(&output.join("docket-custody.json"), &custody)?;
    write_canonical(&output.join("docket-settlement.json"), &settlement)?;
    std::fs::write(output.join("docket-inspection.json"), inspection_raw)
        .map_err(|error| error.to_string())?;
    write_canonical(&output.join("executor-dispatch.json"), &dispatch)?;
    write_canonical(&output.join("executor-outcome.json"), &executor_outcome)?;
    std::fs::write(output.join("systemd-evidence.json"), &systemd_evidence)
        .map_err(|error| error.to_string())?;
    write_canonical(
        &output.join("ag-history.json"),
        &reopened.history().map_err(|e| e.to_string())?,
    )?;
    write_canonical(&output.join("ag-replay.json"), &replay)?;
    write_canonical(
        &output.join("composition-result.json"),
        &json!({
            "schema": "constellation.operator_beta.docket_systemd_composition_result.v1",
            "run_id": run_id,
            "disposition": "SETTLED",
            "ag_spends": replay.ag_spends,
            "docket_attempts": replay.docket_attempts,
            "settlements": replay.settlements,
            "issuance": issuance.issuance,
            "attempt": custody.attempt,
            "marker": custody.executor_marker,
            "work": scenario.work,
            "subject": scenario.subject,
            "scope": scenario.scope,
            "receipt": settlement.receipt,
            "docket_status": inspection["record"]["status"],
            "duplicate_same_custody": true,
            "ag_restart_exact": true,
            "executor_reconcile_exact": true
        }),
    )?;
    println!("SETTLED");
    Ok(())
}
