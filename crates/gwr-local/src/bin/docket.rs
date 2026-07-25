//! The operator docket CLI: the first usable governed-work workflow.
//!
//! Every command is a thin wrapper over the runtime services; nothing here
//! holds authority of its own. State lives under `--state <dir>`:
//! `state.sqlite`, `artifacts/`, `journals/`, `provenance/`, `standing.key`.

use gwr_core::digest::Sha256Digest;
use gwr_core::domain::evidence::Claim;
use gwr_core::domain::standing::{StandingAct, StandingGrant, StandingScope};
use gwr_core::effect_spec::GitRefEffect;
use gwr_core::ids::*;
use gwr_core::lifecycle::AttemptState;
use gwr_core::observation_plan::ObservationPlan;
use gwr_core::preparation::{PreparationRun, PreparationStatus};
use gwr_core::prepared_attempt::PreparedAttempt;
use gwr_core::work_request::{ClockReading, CommitHash, RefName, RepositoryIdentity, WorkRequest};
use gwr_local::adapters::{FsArtifactStore, FsProvenanceSink, HashChainIds, SystemClock};
use gwr_local::broker::SubprocessGitBroker;
use gwr_local::capabilities::StandingTokenCodec;
use gwr_local::providers::fake::{Script, ScriptedProvider};
use gwr_local::store::SqliteStore;
use gwr_runtime::ports::adapters::{Clock, IdSource};
use gwr_runtime::ports::labor_provider::BoundedAssignment;
use gwr_runtime::ports::store::Store;
use gwr_runtime::services::dispatch::{dispatch, DispatchOutcome};
use gwr_runtime::services::preparation::{run_preparation, PreparationResult};
use gwr_runtime::services::ratification::ratify;
use gwr_runtime::services::reconcile::reconcile;
use gwr_runtime::services::reliance::{rely_review_queue, RelyError};
use gwr_runtime::services::reservation::reserve;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("refused/error: {e}");
            std::process::exit(1);
        }
    }
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn need(args: &[String], name: &str) -> Result<String, String> {
    flag(args, name).ok_or_else(|| format!("missing {name}"))
}

fn hex16s(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse16(s: &str) -> Result<[u8; 16], String> {
    let s = s.rsplit('-').next().unwrap_or(s);
    if s.len() != 32 {
        return Err(format!("bad id {s}"));
    }
    let mut out = [0u8; 16];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|_| "bad id")?;
        out[i] = u8::from_str_radix(s, 16).map_err(|_| "bad id")?;
    }
    Ok(out)
}

fn parse_digest(s: &str) -> Result<Sha256Digest, String> {
    if s.len() != 64 {
        return Err("bad digest".into());
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|_| "bad digest")?;
        out[i] = u8::from_str_radix(s, 16).map_err(|_| "bad digest")?;
    }
    Ok(Sha256Digest::from_bytes(out))
}

fn actor_id(name: &str) -> ActorId {
    let d = gwr_core::digest::Transcript::new("gwr:actor:v1")
        .text_field("name", name)
        .finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(&d.as_bytes()[..16]);
    ActorId::from_bytes(b)
}

struct State {
    dir: PathBuf,
    store: SqliteStore,
    ids: HashChainIds,
    clock: SystemClock,
}

impl State {
    fn open(args: &[String]) -> Result<Self, String> {
        let dir = PathBuf::from(need(args, "--state")?);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let store = SqliteStore::open(&dir.join("state.sqlite")).map_err(|e| format!("{e:?}"))?;
        Ok(Self {
            dir,
            store,
            ids: HashChainIds::new(),
            clock: SystemClock,
        })
    }

    fn codec(&mut self) -> Result<StandingTokenCodec, String> {
        let key_path = self.dir.join("standing.key");
        let key: [u8; 32] = if key_path.exists() {
            let bytes = std::fs::read(&key_path).map_err(|e| e.to_string())?;
            bytes.try_into().map_err(|_| "bad standing.key")?
        } else {
            let mut key = [0u8; 32];
            key[..16].copy_from_slice(&self.ids.fresh16());
            key[16..].copy_from_slice(&self.ids.fresh16());
            std::fs::write(&key_path, key).map_err(|e| e.to_string())?;
            key
        };
        Ok(StandingTokenCodec::new(key))
    }

    fn broker(&self) -> SubprocessGitBroker {
        let bin = std::env::var("GWR_BROKER_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                std::env::current_exe()
                    .expect("current exe")
                    .with_file_name("gwr-git-broker")
            });
        SubprocessGitBroker::new(bin, self.dir.join("journals"), self.dir.join("artifacts"))
    }
}

fn state_tag(state: &AttemptState) -> &'static str {
    match state {
        AttemptState::Prepared => "prepared",
        AttemptState::Ratified { .. } => "ratified",
        AttemptState::Reserved { .. } => "reserved",
        AttemptState::Dispatching { .. } => "dispatching",
        AttemptState::Committed { .. } => "committed",
        AttemptState::DispatchRefused { .. } => "dispatch_refused",
        AttemptState::Indeterminate { .. } => "indeterminate",
        AttemptState::CommittedViaRecovery { .. } => "committed_via_recovery",
        AttemptState::ProvenNotCommitted { .. } => "proven_not_committed",
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let cmd: Vec<&str> = args
        .iter()
        .take_while(|a| !a.starts_with("--"))
        .map(String::as_str)
        .collect();
    match cmd.as_slice() {
        ["request", "create"] => {
            let mut st = State::open(args)?;
            let wr = WorkRequest {
                id: WorkRequestId::from_bytes(st.ids.fresh16()),
                repository: RepositoryIdentity::new(need(args, "--repo")?),
                target_ref: RefName::new(need(args, "--target-ref")?),
                goal: need(args, "--goal")?,
                created_at: st.clock.now(),
            };
            st.store
                .create_work_request(&wr)
                .map_err(|e| format!("{e:?}"))?;
            println!("work_request: {}", hex16s(wr.id.as_bytes()));
            Ok(())
        }
        ["prepare", "start"] => {
            let mut st = State::open(args)?;
            let request = WorkRequestId::from_bytes(parse16(&need(args, "--request")?)?);
            let wr = st
                .store
                .get_work_request(request)
                .map_err(|e| format!("{e:?}"))?;
            let deadline_ms: u64 = flag(args, "--deadline-ms")
                .map(|s| s.parse().unwrap_or(600_000))
                .unwrap_or(600_000);
            let now = st.clock.now();
            let run = PreparationRun {
                id: PreparationRunId::from_bytes(st.ids.fresh16()),
                work_request: request,
                started_at: now,
                deadline: ClockReading(now.0 + deadline_ms),
                status: PreparationStatus::Running,
            };
            st.store
                .create_preparation_run(&run)
                .map_err(|e| format!("{e:?}"))?;
            let basis = flag(args, "--basis").unwrap_or_default();
            let workspace = st.dir.join("workspace");
            let assignment = BoundedAssignment {
                preparation_run: run.id,
                goal: wr.goal.clone(),
                basis: CommitHash::new(basis.clone()),
                workspace: workspace.clone(),
                deadline: run.deadline,
            };
            let mut artifacts = FsArtifactStore::new(st.dir.join("artifacts"))?;
            let mut provenance = FsProvenanceSink::new(st.dir.join("provenance"))?;
            let clock = SystemClock;
            let mut ids = HashChainIds::new();
            let mut provider: Box<dyn gwr_runtime::ports::labor_provider::LaborProvider> =
                match flag(args, "--provider").as_deref() {
                    Some("codex") => {
                        gwr_local::providers::codex::populate_workspace(
                            wr.repository.as_str(),
                            &basis,
                            &workspace,
                        )?;
                        let mut p = gwr_local::providers::codex::CodexExecProvider::new();
                        if let Some(bin) = std::env::var_os("GWR_CODEX_BIN") {
                            p.codex_bin = PathBuf::from(bin);
                        }
                        if let Some(t) = flag(args, "--timeout-ms") {
                            p.timeout = std::time::Duration::from_millis(
                                t.parse().map_err(|_| "bad --timeout-ms")?,
                            );
                        }
                        Box::new(p)
                    }
                    _ => {
                        let patch_file = need(args, "--fake-patch")?;
                        let patch = std::fs::read(&patch_file).map_err(|e| e.to_string())?;
                        Box::new(ScriptedProvider::new(Script::Produce {
                            patch,
                            reported_digest: None,
                        }))
                    }
                };
            let result = run_preparation(
                &mut st.store,
                provider.as_mut(),
                &run,
                &assignment,
                &mut artifacts,
                &mut provenance,
                &clock,
                &mut ids,
            )
            .map_err(|e| format!("{e:?}"))?;
            println!("preparation_run: {}", hex16s(run.id.as_bytes()));
            match result {
                PreparationResult::CandidateIngested { artifact, .. } => {
                    println!("candidate: {}", hex16s(artifact.id.as_bytes()));
                    println!("candidate_digest: {}", artifact.content_digest.to_hex());
                }
                other => println!("outcome: {other:?}"),
            }
            Ok(())
        }
        ["prepare", "poll"] => {
            let mut st = State::open(args)?;
            let run = PreparationRunId::from_bytes(parse16(&need(args, "--run")?)?);
            let run = st
                .store
                .get_preparation_run(run)
                .map_err(|e| format!("{e:?}"))?;
            println!("status: {:?}", run.status);
            Ok(())
        }
        ["candidate", "admit"] => {
            let mut st = State::open(args)?;
            let request = WorkRequestId::from_bytes(parse16(&need(args, "--request")?)?);
            let wr = st
                .store
                .get_work_request(request)
                .map_err(|e| format!("{e:?}"))?;
            let candidate = CandidateArtifactId::from_bytes(parse16(&need(args, "--candidate")?)?);
            let cand = st
                .store
                .get_candidate(candidate)
                .map_err(|e| format!("{e:?}"))?;
            let basis = CommitHash::new(need(args, "--basis")?);
            let allow: Vec<String> = args
                .iter()
                .enumerate()
                .filter(|(_, a)| *a == "--allow")
                .filter_map(|(i, _)| args.get(i + 1).cloned())
                .collect();
            let observe_cmd = need(args, "--observe")?;
            let attempt = PreparedAttempt::admit(
                AttemptId::from_bytes(st.ids.fresh16()),
                request,
                candidate,
                wr.repository.clone(),
                basis.clone(),
                cand.content_digest,
                GitRefEffect {
                    target_ref: wr.target_ref.clone(),
                    expected_basis: basis,
                    patch_digest: cand.content_digest,
                    allowed_paths: allow,
                },
                ObservationPlan {
                    argv: observe_cmd.split_whitespace().map(String::from).collect(),
                    environment_description: "operator workstation".into(),
                },
                st.clock.now(),
            );
            st.store
                .admit_attempt(&attempt)
                .map_err(|e| format!("{e:?}"))?;
            println!("attempt: {}", hex16s(attempt.attempt_id.as_bytes()));
            println!(
                "prepared_attempt_digest: {}",
                attempt.prepared_attempt_digest.to_hex()
            );
            Ok(())
        }
        ["grant", "standing"] => {
            let mut st = State::open(args)?;
            let attempt = AttemptId::from_bytes(parse16(&need(args, "--attempt")?)?);
            let projected = st
                .store
                .get_attempt(attempt)
                .map_err(|e| format!("{e:?}"))?;
            let act = match flag(args, "--act").as_deref() {
                Some("resolve-recovery") => StandingAct::ResolveRecovery,
                _ => StandingAct::Ratify,
            };
            let ttl: u64 = flag(args, "--ttl-ms")
                .map(|s| s.parse().unwrap_or(3_600_000))
                .unwrap_or(3_600_000);
            let grant = StandingGrant::issue(
                StandingGrantId::from_bytes(st.ids.fresh16()),
                StandingScope {
                    actor: actor_id(&need(args, "--actor")?),
                    act,
                    repository: projected.attempt.repository.clone(),
                    attempt_digest: projected.attempt.prepared_attempt_digest,
                },
                ClockReading(st.clock.now().0 + ttl),
            );
            st.store
                .create_standing_grant(&grant)
                .map_err(|e| format!("{e:?}"))?;
            let token = st.codec()?.issue(&grant);
            println!("grant: {}", hex16s(grant.id().as_bytes()));
            println!("token: {token}");
            Ok(())
        }
        ["ratify"] => {
            let mut st = State::open(args)?;
            let attempt = AttemptId::from_bytes(parse16(&need(args, "--attempt")?)?);
            let token = need(args, "--token")?;
            let verified = st
                .codec()?
                .verify(&token)
                .map_err(|e| format!("token integrity: {e:?}"))?;
            let digest = parse_digest(&need(args, "--digest")?)?;
            let basis = CommitHash::new(need(args, "--basis")?);
            let clock = SystemClock;
            let mut ids = HashChainIds::new();
            let receipt = ratify(
                &mut st.store,
                attempt,
                verified.id(),
                actor_id(&need(args, "--actor")?),
                digest,
                basis,
                &clock,
                &mut ids,
            )
            .map_err(|e| format!("{e:?}"))?;
            println!("ratification: {}", hex16s(receipt.ratification.as_bytes()));
            Ok(())
        }
        ["reserve"] => {
            let mut st = State::open(args)?;
            let attempt = AttemptId::from_bytes(parse16(&need(args, "--attempt")?)?);
            let ttl: u64 = flag(args, "--ttl-ms")
                .map(|s| s.parse().unwrap_or(3_600_000))
                .unwrap_or(3_600_000);
            let clock = SystemClock;
            let mut ids = HashChainIds::new();
            let claim = reserve(&mut st.store, attempt, ttl, &clock, &mut ids)
                .map_err(|e| format!("{e:?}"))?;
            println!("reservation: {}", hex16s(claim.id().as_bytes()));
            Ok(())
        }
        ["dispatch"] => {
            let mut st = State::open(args)?;
            let attempt = AttemptId::from_bytes(parse16(&need(args, "--attempt")?)?);
            let mut broker = st.broker();
            let clock = SystemClock;
            let mut ids = HashChainIds::new();
            let outcome = dispatch(&mut st.store, attempt, &mut broker, &clock, &mut ids)
                .map_err(|e| format!("{e:?}"))?;
            match outcome {
                DispatchOutcome::Committed(c) => {
                    println!("outcome: committed");
                    println!("result_commit: {}", c.result_commit.as_str());
                }
                DispatchOutcome::Refused(r) => {
                    println!("outcome: dispatch_refused");
                    println!("ground: {:?}", r.ground);
                }
                DispatchOutcome::Indeterminate(_) => {
                    println!("outcome: indeterminate");
                    println!("note: only recovery evidence plus recovery standing resolves this");
                }
                DispatchOutcome::AlreadyDispatched { state } => {
                    println!("outcome: already_dispatched");
                    println!("state: {}", state_tag(&state));
                }
            }
            Ok(())
        }
        ["observe"] => {
            let mut st = State::open(args)?;
            let attempt = AttemptId::from_bytes(parse16(&need(args, "--attempt")?)?);
            let clock = SystemClock;
            let mut ids = HashChainIds::new();
            let record = gwr_local::observe::observe(&mut st.store, attempt, &clock, &mut ids)
                .map_err(|e| format!("{e:?}"))?;
            println!("observation: {}", hex16s(record.id.as_bytes()));
            println!("exit_status: {}", record.exit_status);
            Ok(())
        }
        ["rely", "review-queue"] => {
            let mut st = State::open(args)?;
            let attempt = AttemptId::from_bytes(parse16(&need(args, "--attempt")?)?);
            let observation = ObservationId::from_bytes(parse16(&need(args, "--observation")?)?);
            let claim = match need(args, "--claim")?.as_str() {
                "effect-and-command" => Claim::ExactResultCommitProducedAndCommandExitedZero,
                "patch-correct" => Claim::PatchIsCorrect,
                "task-complete" => Claim::TaskIsComplete,
                "safe-to-merge" => Claim::SafeToMerge,
                "obligation-discharged" => Claim::ObligationDischarged,
                "work-closed" => Claim::WorkMayBeClosed,
                other => return Err(format!("unknown claim {other}")),
            };
            let clock = SystemClock;
            match rely_review_queue(&mut st.store, attempt, observation, claim, &clock) {
                Ok(adm) => {
                    println!("reliance: admitted");
                    println!("result_commit: {}", adm.result_commit.as_str());
                    Ok(())
                }
                Err(RelyError::Refused(refusal)) => {
                    println!("reliance: refused");
                    println!("refusal: {refusal:?}");
                    Ok(())
                }
                Err(e) => Err(format!("{e:?}")),
            }
        }
        ["reconcile"] => {
            let mut st = State::open(args)?;
            let attempt = AttemptId::from_bytes(parse16(&need(args, "--attempt")?)?);
            let clock = SystemClock;
            let mut ids = HashChainIds::new();
            let rec = reconcile(&mut st.store, attempt, &clock, &mut ids)
                .map_err(|e| format!("{e:?}"))?;
            println!("reconciled: {}", hex16s(rec.attempt.as_bytes()));
            for ob in st
                .store
                .get_residual_obligations(attempt)
                .map_err(|e| format!("{e:?}"))?
            {
                println!("retained_obligation: {:?}", ob.kind);
            }
            Ok(())
        }
        ["recover", "fact"] => {
            let mut st = State::open(args)?;
            let attempt = AttemptId::from_bytes(parse16(&need(args, "--attempt")?)?);
            let clock = SystemClock;
            let mut ids = HashChainIds::new();
            let journal_dir = st.dir.join("journals");
            let fact = gwr_local::recover::produce_fact(
                &mut st.store,
                attempt,
                &journal_dir,
                &clock,
                &mut ids,
            )
            .map_err(|e| format!("{e:?}"))?;
            println!("recovery_fact: {}", hex16s(fact.id.as_bytes()));
            println!("observed_ref: {}", fact.observed_ref.as_str());
            match &fact.expected_result_commit {
                Some(c) => println!("expected_result_commit: {}", c.as_str()),
                None => println!("expected_result_commit: unknown"),
            }
            Ok(())
        }
        ["recover", "resolve"] => {
            let mut st = State::open(args)?;
            let attempt = AttemptId::from_bytes(parse16(&need(args, "--attempt")?)?);
            let fact = RecoveryFactId::from_bytes(parse16(&need(args, "--fact")?)?);
            let token = need(args, "--token")?;
            let verified = st
                .codec()?
                .verify(&token)
                .map_err(|e| format!("token integrity: {e:?}"))?;
            let clock = SystemClock;
            let mut ids = HashChainIds::new();
            let mut evidence =
                gwr_local::recover::GitRecoveryEvidence::new(st.dir.join("journals"));
            let resolution = gwr_runtime::services::recovery::resolve(
                &mut st.store,
                attempt,
                fact,
                verified.id(),
                actor_id(&need(args, "--actor")?),
                &mut evidence,
                &clock,
                &mut ids,
            )
            .map_err(|e| format!("{e:?}"))?;
            println!("resolution: {:?}", resolution.verdict);
            Ok(())
        }
        ["docket", "list"] | ["list"] => {
            let mut st = State::open(args)?;
            let json = has(args, "--json");
            let attempts = st.store.list_attempts().map_err(|e| format!("{e:?}"))?;
            if json {
                let mut rows = Vec::new();
                for id in attempts {
                    let p = st.store.get_attempt(id).map_err(|e| format!("{e:?}"))?;
                    rows.push(format!(
                        "{{\"attempt\":\"{}\",\"state\":\"{}\",\"version\":{}}}",
                        hex16s(id.as_bytes()),
                        state_tag(&p.state),
                        p.version
                    ));
                }
                println!("[{}]", rows.join(","));
            } else {
                for id in attempts {
                    let p = st.store.get_attempt(id).map_err(|e| format!("{e:?}"))?;
                    println!(
                        "attempt {} state {} version {}",
                        hex16s(id.as_bytes()),
                        state_tag(&p.state),
                        p.version
                    );
                }
            }
            Ok(())
        }
        ["docket", "show"] | ["show"] => {
            let mut st = State::open(args)?;
            let attempt = AttemptId::from_bytes(parse16(&need(args, "--attempt")?)?);
            let p = st
                .store
                .get_attempt(attempt)
                .map_err(|e| format!("{e:?}"))?;
            let json = has(args, "--json");
            let timeline = st.store.timeline(attempt).map_err(|e| format!("{e:?}"))?;
            let obligations = st
                .store
                .get_residual_obligations(attempt)
                .map_err(|e| format!("{e:?}"))?;
            let observations = st
                .store
                .get_observations(attempt)
                .map_err(|e| format!("{e:?}"))?;
            if json {
                let tl: Vec<String> = timeline
                    .iter()
                    .map(|t| format!("{{\"seq\":{},\"kind\":\"{}\"}}", t.seq, t.kind))
                    .collect();
                let obs: Vec<String> = observations
                    .iter()
                    .map(|o| {
                        format!(
                            "{{\"observation\":\"{}\",\"exit_status\":{}}}",
                            hex16s(o.id.as_bytes()),
                            o.exit_status
                        )
                    })
                    .collect();
                println!(
                    "{{\"attempt\":\"{}\",\"state\":\"{}\",\"version\":{},\"timeline\":[{}],\"residual_obligations\":{},\"observations\":[{}]}}",
                    hex16s(attempt.as_bytes()),
                    state_tag(&p.state),
                    p.version,
                    tl.join(","),
                    obligations.len(),
                    obs.join(",")
                );
            } else {
                println!("attempt {}", hex16s(attempt.as_bytes()));
                println!("state {}", state_tag(&p.state));
                println!("version {}", p.version);
                for t in &timeline {
                    println!("timeline {} {}", t.seq, t.kind);
                }
                for ob in &obligations {
                    println!("residual_obligation {:?}", ob.kind);
                }
                for o in &observations {
                    println!(
                        "observation {} exit_status {}",
                        hex16s(o.id.as_bytes()),
                        o.exit_status
                    );
                }
            }
            Ok(())
        }
        _ => Err(format!(
            "unknown command {cmd:?}; commands: request create, prepare start, prepare poll, \
             candidate admit, grant standing, ratify, reserve, dispatch, observe, \
             rely review-queue, reconcile, docket list, docket show"
        )),
    }
}
