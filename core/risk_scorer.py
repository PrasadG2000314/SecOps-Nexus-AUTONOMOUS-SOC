"""
Contextual Risk Scoring Engine
Calculates multidimensional risk beyond raw CVSS:
Considers Asset Criticality, Network Exposure, and CISA KEV active exploitation telemetry.
"""
from schemas.alerts import UnifiedAlert, AssetCriticality, NetworkExposure
from config import settings

CRITICALITY_WEIGHTS = {
    AssetCriticality.TIER_0_MISSION_CRITICAL: 1.50,
    AssetCriticality.TIER_1_PRODUCTION: 1.25,
    AssetCriticality.TIER_2_STAGING: 0.90,
    AssetCriticality.TIER_3_INTERNAL_DEV: 0.60
}

EXPOSURE_WEIGHTS = {
    NetworkExposure.PUBLIC_INTERNET: 1.40,
    NetworkExposure.INTERNAL_VPC: 0.90,
    NetworkExposure.AIR_GAPPED: 0.50
}

class ContextualRiskEngine:
    def calculate_score(self, alert: UnifiedAlert) -> float:
        """
        Computes the contextual risk score between 0.0 and 100.0.
        Formula:
        (CVSS_Score * 10) * Asset_Weight * Exposure_Weight + CISA_KEV_Boost
        Capped at 100.0, minimum 0.0.
        """
        cvss = alert.vulnerability.cvss_base_score
        asset_weight = CRITICALITY_WEIGHTS.get(alert.asset.criticality, 1.0)
        exposure_weight = EXPOSURE_WEIGHTS.get(alert.asset.exposure, 1.0)

        # Baseline calculation from 0 to 100
        raw_score = (cvss * 6.5) * asset_weight * exposure_weight

        # CISA KEV (Known Exploited Vulnerabilities) boost
        if alert.vulnerability.cisa_kev_active:
            raw_score += 25.0  # Exploit is weaponized and actively in the wild

        # Clamp between 0.0 and 100.0
        final_score = max(0.0, min(100.0, round(raw_score, 1)))
        return final_score

    def determine_severity(self, score: float) -> str:
        """Derives categorical severity level from the contextual score."""
        if score >= 80.0:
            return "CRITICAL"
        elif score >= 60.0:
            return "HIGH"
        elif score >= 35.0:
            return "MEDIUM"
        else:
            return "LOW"

    def is_auto_containment_permitted(self, score: float, alert: UnifiedAlert) -> bool:
        """
        Determines whether autonomous remediation is safe to execute without human approval.
        Strict Zero Trust Rule:
        - Must be score <= AUTO_CONTAINMENT_MAX_RISK (30.0)
        - Must NOT be Tier 0 Mission Critical
        - Must NOT be an active CISA KEV exploit
        """
        if score > settings.AUTO_CONTAINMENT_MAX_RISK:
            return False
        if alert.asset.criticality == AssetCriticality.TIER_0_MISSION_CRITICAL:
            return False
        if alert.vulnerability.cisa_kev_active:
            return False
        return True

    def evaluate_alert(self, alert: UnifiedAlert) -> UnifiedAlert:
        """Evaluates an alert and updates risk score, severity, and status in place."""
        score = self.calculate_score(alert)
        alert.contextual_risk_score = score
        alert.severity_level = self.determine_severity(score)
        return alert

risk_engine = ContextualRiskEngine()
