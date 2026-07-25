//! The four explicit bridges — and only these four.
//!
//! A bridge is a named, versioned, exact crossing from one domain judgment to
//! another: fixed input type, fixed output type, declared information
//! transported and not transported, required authority, typed refusals. There is
//! no generic policy evaluator, no bridge registry, no universal judgment type,
//! and no blanket `From` conversions. An absent bridge means no judgment
//! transfer: where no crossing is declared, the correct output is a first-class
//! reliance refusal, never a default or a pass-through.
//!
//! No bridge transports correctness, merge safety, completion, or obligation
//! discharge.

pub mod observation_to_review_queue;
pub mod recovery_standing_to_resolution;
pub mod reservation_to_dispatch;
pub mod standing_to_ratification;
