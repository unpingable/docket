//! Fixed M3 companion entrypoint; all execution still traverses the existing
//! AG issuance, Docket custody, systemd executor and replay implementation.

#[path = "composition_driver.rs"]
mod composition;
// Build preparation copies the exact enrolled application-owned source here.
#[path = "m3_observation_resolver.rs"]
mod observation;

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use ag_primitives::Digest;
use nq_core::labelwatch_cleanup::Request;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    schema: String,
    action: String,
    unit: String,
    step_sha256: String,
    subject: String,
    scope: String,
    receipt: Option<PathBuf>,
    receipt_id: Option<String>,
    request: Option<Request>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH)
        .expect("qualified fixture requires a post-epoch wall clock")
        .as_millis().try_into().expect("wall-clock milliseconds exceed u64")
}

fn run() -> Result<(), String> {
    let mut arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.len() != 10 {
        return Err("expected DOCKET AG_EFFECTD OUTPUT RUN MACHINE UNIT SUBJECT SCOPE ENROLLMENT ENROLLMENT_SHA256".into());
    }
    let enrolled_sha = arguments.pop().unwrap();
    let path = PathBuf::from(arguments.pop().unwrap());
    let raw = nq_app::bounded_input::read(&path, 2 * 1024 * 1024).map_err(|e| e.to_string())?;
    use sha2::{Digest as _, Sha256};
    if format!("{:x}", Sha256::digest(&raw)) != enrolled_sha {
        return Err("exact root enrollment bytes differ".into());
    }
    let enrollment: Enrollment = nq_protocol::decode_json_document(&raw, 2 * 1024 * 1024).map_err(|e| e.to_string())?;
    if enrollment.schema != "constellation.m3-driver-enrollment/v1"
        || enrollment.step_sha256.len() != 64
        || !enrollment.step_sha256.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        || enrollment.unit != format!("labelwatch-relief-{}.service", enrollment.step_sha256)
        || arguments[5] != enrollment.unit
        || arguments[6] != enrollment.subject
        || arguments[7] != enrollment.scope
    {
        return Err("exact M3 unit/step/subject/scope enrollment differs".into());
    }
    if enrollment.action == "cleanup" {
        let mut resolver = observation::NativeCleanupObservation {
            enrolled: observation::EnrolledCleanup {
                receipt: enrollment.receipt.ok_or("cleanup receipt absent")?,
                expected_receipt_id: enrollment.receipt_id.ok_or("cleanup receipt identity absent")?,
                expected_request: enrollment.request.ok_or("cleanup request absent")?,
                cleanup_step_sha256: enrollment.step_sha256,
                subject: Digest::parse(&enrollment.subject).map_err(|e| e.to_string())?,
                scope: Digest::parse(&enrollment.scope).map_err(|e| e.to_string())?,
            },
        };
        let reference = observation::observation_identity(&resolver.enrolled)?;
        let receipt_raw = nq_app::bounded_input::read(&resolver.enrolled.receipt, 2 * 1024 * 1024).map_err(|e|e.to_string())?;
        let receipt: serde_json::Value = nq_protocol::decode_json_document(&receipt_raw, 2 * 1024 * 1024).map_err(|e|e.to_string())?;
        nq_core::labelwatch_cleanup::replay(&receipt)?;
        if receipt["receipt_id"] != resolver.enrolled.expected_receipt_id {
            return Err("execution expiry source is not the enrolled receipt".into());
        }
        let source: nq_core::labelwatch_cleanup::CleanupSource = nq_protocol::decode_json_document(
            receipt["source_utf8"].as_str().ok_or("cleanup source absent")?.as_bytes(), 2 * 1024 * 1024,
        ).map_err(|e|e.to_string())?;
        let started = u64::try_from(source.currentness_started_at.timestamp_millis()).map_err(|e|e.to_string())?;
        let expires_at = started.checked_add(u64::from(resolver.enrolled.expected_request.maximum_currentness_age_seconds) * 1000).ok_or("cleanup expiry overflow")?;
        let boundary = composition::ExecutionBoundary { expires_at, observation: reference.clone() };
        composition::run_with_admission(arguments.into_iter(), |engine, scenario| {
            if scenario.subject != resolver.enrolled.subject || scenario.scope != resolver.enrolled.scope {
                return Err("scenario differs from native prerequisite enrollment".into());
            }
            composition::authorize_with_observation(engine, scenario, &mut resolver, reference, observation::RESOLVER_ID, now, Some(expires_at))
        }, now, Some(boundary))
    } else {
        if !matches!(enrollment.action.as_str(), "stage" | "replace" | "verify-installed" | "verify-service" | "release" | "rollback-pre-ingest" | "reconcile-cleanup")
            || enrollment.receipt.is_some() || enrollment.receipt_id.is_some() || enrollment.request.is_some()
        {
            return Err("unknown fixture step or misplaced native cleanup prerequisite".into());
        }
        // These explicit fixture admissions qualify execution plumbing only.
        // They do not establish the final cleanup factual predicate.
        let mut tick = 5;
        composition::run_with_admission(arguments.into_iter(), composition::authorize, || { tick += 1; tick }, None)
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("M3 composition refused: {error}");
        std::process::exit(1);
    }
}
