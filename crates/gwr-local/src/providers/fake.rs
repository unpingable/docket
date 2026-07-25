//! Two fake providers behind the one neutral contract, proving preparation
//! labor varies independently of the governed lifecycle.

use gwr_core::ids::PreparationRunId;
use gwr_runtime::ports::labor_provider::{
    BoundedAssignment, LaborProvider, PreparationOutcome, PreparationReport, ProvenanceEntry,
    ProviderError, ProviderEvent, SequencedEvent,
};

/// A provider that does exactly what it was scripted to do.
pub struct ScriptedProvider {
    pub script: Script,
    pub cancelled: Vec<PreparationRunId>,
}

#[derive(Clone)]
pub enum Script {
    /// Produce these exact patch bytes, optionally reporting a digest claim.
    Produce {
        patch: Vec<u8>,
        reported_digest: Option<String>,
    },
    Refuse(String),
    Fail(String),
    Die(String),
    /// Emit a broken (non-increasing) event sequence around a candidate.
    DuplicateSequence {
        patch: Vec<u8>,
    },
}

impl ScriptedProvider {
    pub fn new(script: Script) -> Self {
        Self {
            script,
            cancelled: Vec::new(),
        }
    }
}

impl LaborProvider for ScriptedProvider {
    fn prepare(
        &mut self,
        _assignment: &BoundedAssignment,
    ) -> Result<PreparationReport, ProviderError> {
        let ok_events = vec![
            SequencedEvent {
                seq: 0,
                event: ProviderEvent::Started,
            },
            SequencedEvent {
                seq: 1,
                event: ProviderEvent::ToolRequest("write governed target directly".into()),
            },
            SequencedEvent {
                seq: 2,
                event: ProviderEvent::CandidateReady,
            },
        ];
        match &self.script {
            Script::Produce {
                patch,
                reported_digest,
            } => {
                let mut provenance = vec![ProvenanceEntry {
                    label: "explanation".into(),
                    content: "scripted candidate".into(),
                }];
                if let Some(d) = reported_digest {
                    provenance.push(ProvenanceEntry {
                        label: crate::REPORTED_DIGEST_LABEL.into(),
                        content: d.clone(),
                    });
                }
                Ok(PreparationReport {
                    events: ok_events,
                    outcome: PreparationOutcome::Candidate {
                        patch: patch.clone(),
                    },
                    provenance,
                })
            }
            Script::Refuse(why) => Ok(PreparationReport {
                events: vec![SequencedEvent {
                    seq: 0,
                    event: ProviderEvent::Started,
                }],
                outcome: PreparationOutcome::Refused {
                    explanation: why.clone(),
                },
                provenance: vec![ProvenanceEntry {
                    label: "refusal_explanation".into(),
                    content: why.clone(),
                }],
            }),
            Script::Fail(why) => Ok(PreparationReport {
                events: vec![SequencedEvent {
                    seq: 0,
                    event: ProviderEvent::Started,
                }],
                outcome: PreparationOutcome::Failed {
                    reason: why.clone(),
                },
                provenance: vec![],
            }),
            Script::Die(why) => Err(ProviderError::Died(why.clone())),
            Script::DuplicateSequence { patch } => Ok(PreparationReport {
                events: vec![
                    SequencedEvent {
                        seq: 0,
                        event: ProviderEvent::Started,
                    },
                    SequencedEvent {
                        seq: 0,
                        event: ProviderEvent::CandidateReady,
                    },
                ],
                outcome: PreparationOutcome::Candidate {
                    patch: patch.clone(),
                },
                provenance: vec![],
            }),
        }
    }

    fn cancel(&mut self, run: PreparationRunId) {
        self.cancelled.push(run);
    }
}

/// A second, structurally different provider: it derives its patch from the
/// assignment goal instead of a script. Same contract, no core changes.
pub struct GoalEchoProvider;

impl LaborProvider for GoalEchoProvider {
    fn prepare(
        &mut self,
        assignment: &BoundedAssignment,
    ) -> Result<PreparationReport, ProviderError> {
        let patch = format!("# patch for goal: {}\n", assignment.goal).into_bytes();
        Ok(PreparationReport {
            events: vec![
                SequencedEvent {
                    seq: 0,
                    event: ProviderEvent::Started,
                },
                SequencedEvent {
                    seq: 5,
                    event: ProviderEvent::CandidateReady,
                },
            ],
            outcome: PreparationOutcome::Candidate { patch },
            provenance: vec![ProvenanceEntry {
                label: "explanation".into(),
                content: format!("echoed goal '{}'", assignment.goal),
            }],
        })
    }
}
