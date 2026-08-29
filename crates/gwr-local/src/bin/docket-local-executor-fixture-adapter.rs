//! Native ELF adapter used only by local executor-process qualification.

use rusqlite::Connection;
use serde_json::Value;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::time::Duration;

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(66);
    }
}

fn run() -> Result<(), String> {
    let operation = std::env::args()
        .nth(1)
        .filter(|value| value == "execute" || value == "reconcile")
        .ok_or_else(|| "fixture-usage".to_owned())?;
    if std::env::args().nth(2).is_some() {
        return Err("fixture-unexpected-pathname-config".to_owned());
    }
    let mut framed = Vec::new();
    std::io::stdin()
        .read_to_end(&mut framed)
        .map_err(|error| format!("fixture-stdin:{error}"))?;
    if framed.len() < 8 {
        return Err("fixture-frame-truncated".to_owned());
    }
    let config_length = usize::try_from(u64::from_be_bytes(
        framed[..8].try_into().expect("eight-byte prefix"),
    ))
    .map_err(|_| "fixture-config-length".to_owned())?;
    let boundary = 8_usize
        .checked_add(config_length)
        .filter(|value| *value <= framed.len())
        .ok_or_else(|| "fixture-config-truncated".to_owned())?;
    let config: Value = serde_json::from_slice(&framed[8..boundary])
        .map_err(|error| format!("fixture-config:{error}"))?;
    let dispatch: Value = serde_json::from_slice(&framed[boundary..])
        .map_err(|error| format!("fixture-dispatch:{error}"))?;
    let field = |name: &str| -> Result<&str, String> {
        config[name]
            .as_str()
            .ok_or_else(|| format!("fixture-config-field:{name}"))
    };
    let dispatch_field = |name: &str| -> Result<&str, String> {
        dispatch[name]
            .as_str()
            .ok_or_else(|| format!("fixture-dispatch-field:{name}"))
    };

    if config["require_reservation"].as_bool() == Some(true) {
        let connection =
            Connection::open(field("state_database")?).map_err(|error| error.to_string())?;
        let row: (String, String) = connection
            .query_row(
                "SELECT marker,status FROM local_governed_executor_attempt WHERE attempt=?1",
                [dispatch_field("attempt")?],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| format!("fixture-reservation:{error}"))?;
        let allowed = row.0 == dispatch_field("marker")?
            && (row.1 == "dispatched" || (operation == "reconcile" && row.1 == "indeterminate"));
        if !allowed {
            return Err("reservation-not-visible-before-adapter".to_owned());
        }
    }

    let mut log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(field("operation_log")?)
        .map_err(|error| format!("fixture-log-open:{error}"))?;
    writeln!(log, "{operation}").map_err(|error| format!("fixture-log-write:{error}"))?;
    log.sync_all()
        .map_err(|error| format!("fixture-log-sync:{error}"))?;

    let behavior = field(&format!("{operation}_behavior"))?;
    match behavior {
        "refuse" => return Err("deterministic-adapter-refusal".to_owned()),
        "cancel" => std::process::abort(),
        "slow_success" => std::thread::sleep(Duration::from_millis(500)),
        "wait_for_release" => {
            std::fs::write(field("adapter_pid")?, format!("{}\n", std::process::id()))
                .map_err(|error| format!("fixture-pid-write:{error}"))?;
            let release = field("release_adapter")?;
            let mut observed = false;
            for _ in 0..1000 {
                if std::path::Path::new(release).exists() {
                    observed = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            if !observed {
                return Err("fixture-release-timeout".to_owned());
            }
        }
        "oversized" => {
            std::io::stdout()
                .write_all(&vec![b'x'; 1_048_577])
                .map_err(|error| error.to_string())?;
            return Ok(());
        }
        "replace_staged_and_refuse" => {
            let path = field("staged_path")?;
            let replacement = format!("{path}.replacement");
            std::fs::write(&replacement, b"unbound staged pathname fixture\n")
                .map_err(|error| error.to_string())?;
            std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o500))
                .map_err(|error| error.to_string())?;
            std::fs::rename(replacement, path).map_err(|error| error.to_string())?;
            return Err("staged-path-replaced-after-open".to_owned());
        }
        "replace_sources_and_refuse" => {
            std::fs::write(
                field("source_program")?,
                b"unbound source program fixture\n",
            )
            .map_err(|error| error.to_string())?;
            std::fs::write(field("source_config")?, b"{}\n").map_err(|error| error.to_string())?;
            return Err("source-paths-replaced-after-resolution".to_owned());
        }
        "duplicate_outcome" => {
            let text = format!(
                "{{\"attempt\":\"{}\",\"attempt\":\"{}\",\"marker\":\"{}\",\"outcome\":\"success\",\"receipt\":\"{}\"}}\n",
                dispatch_field("attempt")?,
                dispatch_field("attempt")?,
                dispatch_field("marker")?,
                field(&format!("{operation}_receipt"))?,
            );
            print!("{text}");
            return Ok(());
        }
        "success" | "failure" | "indeterminate" | "substitute_marker" => {}
        other => return Err(format!("fixture-behavior:{other}")),
    }
    let outcome = if behavior == "slow_success"
        || behavior == "wait_for_release"
        || behavior == "substitute_marker"
    {
        "success"
    } else {
        behavior
    };
    let marker = if behavior == "substitute_marker" {
        format!("sha256:{}", "f".repeat(64))
    } else {
        dispatch_field("marker")?.to_owned()
    };
    let value = serde_json::json!({
        "attempt": dispatch_field("attempt")?,
        "marker": marker,
        "outcome": outcome,
        "receipt": field(&format!("{operation}_receipt"))?,
    });
    println!(
        "{}",
        serde_json::to_string(&value).map_err(|error| error.to_string())?
    );
    Ok(())
}
