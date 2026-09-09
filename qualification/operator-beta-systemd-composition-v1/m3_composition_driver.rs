//! Fixed M3 companion entrypoint; all execution still traverses the existing
//! AG issuance, Docket custody, systemd executor and replay implementation.

#[path = "composition_driver.rs"]
mod composition;
// Build preparation copies the exact enrolled application-owned source here.
#[path = "m3_observation_resolver.rs"]
mod observation;

use ag_primitives::Digest;
use nq_core::labelwatch_cleanup::Request;
use serde::Deserialize;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    schema: String,
    action: String,
    unit: String,
    step_sha256: String,
    step: PathBuf,
    qualification_interruption: Option<String>,
    qualification_restore_substitution: bool,
    subject: String,
    scope: String,
    receipt: Option<PathBuf>,
    receipt_id: Option<String>,
    request: Option<Request>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("qualified fixture requires a post-epoch wall clock")
        .as_millis()
        .try_into()
        .expect("wall-clock milliseconds exceed u64")
}

fn input(path: &std::path::Path) -> Result<(serde_json::Value, Vec<u8>), String> {
    let raw = nq_app::bounded_input::read(path, 2 * 1024 * 1024).map_err(|e| e.to_string())?;
    let value =
        nq_protocol::decode_json_document(&raw, 2 * 1024 * 1024).map_err(|e| e.to_string())?;
    Ok((value, raw))
}

fn hex_sha(raw: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    format!("{:x}", Sha256::digest(raw))
}

// Exact Python ensure_ascii JSON for this closed fixture's integer/string
// records, without a trailing newline. Non-integral numbers are not part of
// its manifest/binding schema and are refused rather than normalized by JCS.
fn app_bytes(value: &serde_json::Value) -> Result<Vec<u8>, String> {
    use serde_json::Value;
    fn string(text: &str) -> Result<String, String> {
        let encoded = serde_json::to_string(text).map_err(|e| e.to_string())?;
        let mut out = String::new();
        for character in encoded.chars() {
            if u32::from(character) >= 127 {
                let mut units = [0; 2];
                for word in character.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{word:04x}"));
                }
            } else {
                out.push(character);
            }
        }
        Ok(out)
    }
    let text =
        match value {
            Value::Null => "null".into(),
            Value::Bool(value) => value.to_string(),
            Value::Number(value) if value.is_i64() || value.is_u64() => value.to_string(),
            Value::Number(_) => {
                return Err("non-integral value outside fixed M3 manifest/binding schema".into())
            }
            Value::String(value) => string(value)?,
            Value::Array(values) => format!(
                "[{}]",
                values
                    .iter()
                    .map(|value| app_bytes(value)
                        .map(|raw| String::from_utf8(raw).expect("ASCII JSON")))
                    .collect::<Result<Vec<_>, _>>()?
                    .join(",")
            ),
            Value::Object(values) => {
                let mut entries: Vec<_> = values.iter().collect();
                entries.sort_by(|a, b| a.0.cmp(b.0));
                format!(
                    "{{{}}}",
                    entries
                        .into_iter()
                        .map(|(key, value)| Ok(format!(
                            "{}:{}",
                            string(key)?,
                            String::from_utf8(app_bytes(value)?).expect("ASCII JSON")
                        )))
                        .collect::<Result<Vec<_>, String>>()?
                        .join(",")
                )
            }
        };
    Ok(text.into_bytes())
}

fn bind_cleanup(step: &serde_json::Value, request: &Request) -> Result<(), String> {
    use serde_json::{json, Value};
    let request = serde_json::to_value(request).map_err(|e| e.to_string())?;
    let held = &request["held_request"];
    for (request_key, step_key) in [
        ("operation", "operation"),
        ("source", "source"),
        ("original", "original"),
        ("application_revision", "revision"),
        ("original_identity", "source_identity"),
    ] {
        if held[request_key] != step[step_key] {
            return Err("cleanup factual request belongs to another step".into());
        }
    }
    let cut = hex_sha(&app_bytes(&step["expected"])?);
    if held["expected_cut_sha256"] != cut
        || held["phase"] != "pre_ingest"
        || request["backup"] != step["backup"]
        || request["restore"] != step["restore"]
    {
        return Err("cleanup factual cut/phase/paths differ".into());
    }
    let hold = json!({"schema":"labelwatch.maintenance-hold/v1", "operation":step["operation"],
        "database":step["source"], "manifest_sha256":cut, "application_revision":step["revision"]});
    let hold_sha = hex_sha(&app_bytes(&hold)?);
    if request["expected_hold_sha256"] != hold_sha {
        return Err("cleanup hold identity differs".into());
    }
    let mut writers = serde_json::Map::new();
    for role in ["main", "discovery"] {
        let path = step["ready_records"][role]
            .as_str()
            .ok_or("enrolled readiness missing")?;
        let (ready, _) = input(std::path::Path::new(path))?;
        if ready.as_object().map(|value| value.len()) != Some(7)
            || ready["schema"] != "labelwatch.held-writer-ready/v1"
            || ready["operation"] != step["operation"]
            || ready["role"] != role
            || ready["hold_sha256"] != hold_sha
            || ready["verification_sha256"] != cut
        {
            return Err("readiness belongs to another operation/role/hold/cut".into());
        }
        writers.insert(
            role.into(),
            json!({"pid":ready["pid"], "start_ticks":ready["start_ticks"]}),
        );
    }
    if held["writer_identities"] != Value::Object(writers) {
        return Err("cleanup writer identities differ".into());
    }
    let mut basis = step.as_object().ok_or("step is not an object")?.clone();
    for key in [
        "action",
        "predecessor",
        "predecessor_sha256",
        "ready_records",
    ] {
        basis.remove(key);
    }
    let binding = hex_sha(&app_bytes(&Value::Object(basis))?);
    let mut current = step.clone();
    let mut replacement = None;
    for _ in 0..4 {
        let path = current["predecessor"]
            .as_str()
            .ok_or("cleanup predecessor missing")?;
        let (previous, raw) = input(std::path::Path::new(path))?;
        if current["predecessor_sha256"] != hex_sha(&raw)
            || previous["operation"] != step["operation"]
            || previous["binding_sha256"] != binding
        {
            return Err("cleanup predecessor custody differs".into());
        }
        if replacement.is_none() {
            replacement = Some(previous["detail"]["replacement"]["identity"].clone());
        }
        if previous["action"] == "stage" {
            let replacement = replacement.ok_or("replacement identity missing")?;
            if held["replacement_device"] != replacement["device"]
                || held["replacement_inode"] != replacement["inode"]
                || request["backup_identity"] != previous["detail"]["backup"]["backup"]["identity"]
                || request["restore_identity"]
                    != previous["detail"]["backup"]["restored"]["identity"]
            {
                return Err(
                    "cleanup copy/replacement identity differs from actual predecessors".into(),
                );
            }
            return Ok(());
        }
        let sha = previous["step_sha256"]
            .as_str()
            .ok_or("predecessor step identity missing")?;
        if sha.len() != 64
            || !sha
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err("malformed predecessor identity".into());
        }
        let path = std::path::Path::new(step["source"].as_str().ok_or("source absent")?)
            .parent()
            .ok_or("source parent absent")?
            .join("enrollment-candidates")
            .join(sha)
            .join("step.json");
        let (next, raw) = input(&path)?;
        if hex_sha(&raw) != sha {
            return Err("predecessor input bytes differ".into());
        }
        current = next;
    }
    Err("exact staging predecessor not found in bounded chain".into())
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
    let enrollment: Enrollment =
        nq_protocol::decode_json_document(&raw, 2 * 1024 * 1024).map_err(|e| e.to_string())?;
    let step_raw = nq_app::bounded_input::read(&enrollment.step, 2 * 1024 * 1024)
        .map_err(|e| e.to_string())?;
    let step: serde_json::Value =
        nq_protocol::decode_json_document(&step_raw, 2 * 1024 * 1024).map_err(|e| e.to_string())?;
    if format!("{:x}", Sha256::digest(&step_raw)) != enrollment.step_sha256
        || step["schema"] != "labelwatch.sqlite-relief-step/v1"
        || step["action"] != enrollment.action
    {
        return Err("admission action differs from exact executed step bytes".into());
    }
    let suffix = match (
        enrollment.qualification_interruption.as_deref(),
        enrollment.qualification_restore_substitution,
    ) {
        (None, false) => String::new(),
        (None, true) if enrollment.action == "stage" => "-q-restore-substitution".into(),
        (Some(cut), false)
            if matches!(
                cut,
                "before_started"
                    | "after_started"
                    | "before_terminal"
                    | "after_terminal"
                    | "after_original_rename"
                    | "after_replacement_rename"
                    | "after_backup_sync"
                    | "after_restore_sync"
                    | "after_staging_sync"
                    | "before_cleanup_unlink"
                    | "after_cleanup_unlink"
                    | "after_cleanup_authorized"
                    | "after_release_record"
            ) =>
        {
            format!("-q-{cut}")
        }
        _ => return Err("unknown or conflicting sealed qualification mode".into()),
    };
    if enrollment.schema != "constellation.m3-driver-enrollment/v1"
        || enrollment.step_sha256.len() != 64
        || !enrollment
            .step_sha256
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        || enrollment.unit
            != format!(
                "labelwatch-relief-{}{suffix}.service",
                enrollment.step_sha256
            )
        || arguments[5] != enrollment.unit
        || arguments[6] != enrollment.subject
        || arguments[7] != enrollment.scope
    {
        return Err("exact M3 unit/step/subject/scope enrollment differs".into());
    }
    if enrollment.action == "cleanup" {
        bind_cleanup(
            &step,
            enrollment
                .request
                .as_ref()
                .ok_or("cleanup request absent")?,
        )?;
        let mut resolver = observation::NativeCleanupObservation {
            enrolled: observation::EnrolledCleanup {
                receipt: enrollment.receipt.ok_or("cleanup receipt absent")?,
                expected_receipt_id: enrollment
                    .receipt_id
                    .ok_or("cleanup receipt identity absent")?,
                expected_request: enrollment.request.ok_or("cleanup request absent")?,
                cleanup_step_sha256: enrollment.step_sha256,
                subject: Digest::parse(&enrollment.subject).map_err(|e| e.to_string())?,
                scope: Digest::parse(&enrollment.scope).map_err(|e| e.to_string())?,
            },
        };
        let reference = observation::observation_identity(&resolver.enrolled)?;
        let receipt_raw = nq_app::bounded_input::read(&resolver.enrolled.receipt, 2 * 1024 * 1024)
            .map_err(|e| e.to_string())?;
        let receipt: serde_json::Value =
            nq_protocol::decode_json_document(&receipt_raw, 2 * 1024 * 1024)
                .map_err(|e| e.to_string())?;
        nq_core::labelwatch_cleanup::replay(&receipt)?;
        if receipt["receipt_id"] != resolver.enrolled.expected_receipt_id {
            return Err("execution expiry source is not the enrolled receipt".into());
        }
        let source: nq_core::labelwatch_cleanup::CleanupSource = nq_protocol::decode_json_document(
            receipt["source_utf8"]
                .as_str()
                .ok_or("cleanup source absent")?
                .as_bytes(),
            2 * 1024 * 1024,
        )
        .map_err(|e| e.to_string())?;
        let started = u64::try_from(source.currentness_started_at.timestamp_millis())
            .map_err(|e| e.to_string())?;
        let expires_at = started
            .checked_add(
                u64::from(
                    resolver
                        .enrolled
                        .expected_request
                        .maximum_currentness_age_seconds,
                ) * 1000,
            )
            .ok_or("cleanup expiry overflow")?;
        let boundary = composition::ExecutionBoundary {
            expires_at,
            observation: reference.clone(),
        };
        composition::run_with_admission(
            arguments.into_iter(),
            |engine, scenario| {
                if scenario.subject != resolver.enrolled.subject
                    || scenario.scope != resolver.enrolled.scope
                {
                    return Err("scenario differs from native prerequisite enrollment".into());
                }
                composition::authorize_with_observation(
                    engine,
                    scenario,
                    &mut resolver,
                    reference,
                    observation::RESOLVER_ID,
                    now,
                    Some(expires_at),
                )
            },
            now,
            Some(boundary),
        )
    } else {
        if !matches!(
            enrollment.action.as_str(),
            "stage"
                | "replace"
                | "verify-installed"
                | "verify-service"
                | "release"
                | "rollback-pre-ingest"
                | "reconcile-cleanup"
        ) || enrollment.receipt.is_some()
            || enrollment.receipt_id.is_some()
            || enrollment.request.is_some()
        {
            return Err("unknown fixture step or misplaced native cleanup prerequisite".into());
        }
        // These explicit fixture admissions qualify execution plumbing only.
        // They do not establish the final cleanup factual predicate.
        let mut tick = 5;
        composition::run_with_admission(
            arguments.into_iter(),
            composition::authorize,
            || {
                tick += 1;
                tick
            },
            None,
        )
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("M3 composition refused: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn fixed_manifest_bytes_match_python_ascii_encoding_without_newline() {
        let value =
            serde_json::json!({"z":"é😀\u{7f}\n\t\u{8}\u{c}\r\u{0}\\\"", "a":[1,true,null]});
        let expected = br#"{"a":[1,true,null],"z":"\u00e9\ud83d\ude00\u007f\n\t\b\f\r\u0000\\\""}"#;
        assert_eq!(super::app_bytes(&value).unwrap(), expected);
        assert!(!super::app_bytes(&value).unwrap().ends_with(b"\n"));
        assert!(super::app_bytes(&serde_json::json!(1.25)).is_err());
    }
}
