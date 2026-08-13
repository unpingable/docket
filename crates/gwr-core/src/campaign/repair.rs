//! Historical campaign-stage repair subset law.
//!
//! The campaign-stage repair office is retired. Records carrying its old
//! vocabulary remain decodable for archive inspection, but this module no
//! longer validates them as current repair authority. Governed repair uses
//! the separate closed custody protocol.

use crate::campaign::adjudication::AdjudicationReceipt;
use crate::campaign::proposal::CampaignStageProposal;
use crate::refusal::CampaignRefusal;

/// Retired live validation entrypoint.
///
/// No arrangement of caller-authored or persisted legacy proposal and
/// adjudication records can regain current campaign-stage repair authority.
pub fn validate_repair(
    _repair_proposal: &CampaignStageProposal,
    _original: &CampaignStageProposal,
    _adjudication: &AdjudicationReceipt,
) -> Result<(), CampaignRefusal> {
    Err(CampaignRefusal::LegacyRepairRouteRetired)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::campaign::adjudication::AdjudicationVerdict;
    use crate::campaign::proposal::tests::operator_proposal;
    use crate::digest::Sha256Digest;
    use crate::work_request::ClockReading;

    #[test]
    fn legacy_records_cannot_be_revalidated_as_current_authority() {
        let original = operator_proposal();
        let adjudication = AdjudicationReceipt {
            digest: Sha256Digest::of_bytes(b"historical-adjudication"),
            campaign: original.campaign.clone(),
            stage: original.stage.clone(),
            review_receipt: Sha256Digest::of_bytes(b"historical-review"),
            verdict: AdjudicationVerdict::ExactRepair,
            adjudicator: "historical-adjudicator".into(),
            findings: vec!["finding-1".into()],
            residuals: vec![],
            adjudicated_at: ClockReading(1_000),
        };
        assert_eq!(
            validate_repair(&original, &original, &adjudication),
            Err(CampaignRefusal::LegacyRepairRouteRetired)
        );
    }
}
