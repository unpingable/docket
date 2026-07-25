//! Execution outcome cannot be rewritten by observation: observations are
//! associated records with no path into the execution-state machine.

use gwr_core::digest::Sha256Digest;
use gwr_core::ids::*;
use gwr_core::lifecycle::*;
use gwr_core::observation_plan::ObservationRecord;
use gwr_core::work_request::{ClockReading, CommitHash};

#[test]
fn failing_observation_leaves_commitment_intact() {
    let committed = AttemptState::Prepared
        .ratify(RatificationRef {
            ratification: RatificationId::from_bytes([1; 16]),
            prepared_attempt_digest: Sha256Digest::of_bytes(b"a"),
            standing_use: StandingUseId::from_bytes([2; 16]),
        })
        .unwrap()
        .reserve(ReservationId::from_bytes([3; 16]))
        .unwrap()
        .dispatch(
            ReservationRef {
                reservation: ReservationId::from_bytes([3; 16]),
                reservation_use: ReservationUseId::from_bytes([4; 16]),
            },
            DispatchRef {
                dispatch: DispatchId::from_bytes([5; 16]),
            },
        )
        .unwrap()
        .commit()
        .unwrap();

    // A failing observation is recorded alongside the attempt...
    let obs = ObservationRecord {
        id: ObservationId::from_bytes([6; 16]),
        attempt: AttemptId::from_bytes([7; 16]),
        argv: vec!["cargo".into(), "test".into()],
        working_directory_identity: "fixture".into(),
        result_commit: CommitHash::new("abc"),
        environment_description: "test".into(),
        exit_status: 101,
        stdout_digest: Sha256Digest::of_bytes(b""),
        stderr_digest: Sha256Digest::of_bytes(b"failure"),
        observed_at: ClockReading(1),
    };
    assert!(!obs.succeeded());

    // ...and there is no transition an observation can drive: the state machine
    // has no observation input at all, and Committed is terminal.
    assert!(committed.is_terminal());
    assert!(committed.commit().is_err());
    assert!(committed.mark_indeterminate().is_err());
    assert!(matches!(committed, AttemptState::Committed { .. }));
}
