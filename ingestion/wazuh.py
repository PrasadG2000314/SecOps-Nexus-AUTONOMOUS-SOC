"""
Wazuh EDR & SIEM Ingestion Parser
Translates host-level endpoint detection, brute-force anomalies, and file integrity monitoring (FIM)
alerts into canonical UnifiedAlert instances.
"""
import hashlib
import json
from typing import List, Dict, Any, Optional
from schemas.alerts import UnifiedAlert, SensorSource, AssetInfo, VulnerabilityInfo, AssetCriticality, NetworkExposure

def parse_wazuh_event(data: Dict[str, Any], asset_override: Optional[Dict[str, Any]] = None) -> List[UnifiedAlert]:
    alerts: List[UnifiedAlert] = []
    raw_hash = hashlib.sha256(json.dumps(data, sort_keys=True).encode("utf-8")).hexdigest()

    agent = data.get("agent", {})
    hostname = agent.get("name", "workstation-node")
    ip_addr = agent.get("ip", "10.0.5.89")

    asset_dict = asset_override or {}
    asset = AssetInfo(
        hostname=asset_dict.get("hostname", hostname),
        ip_address=asset_dict.get("ip_address", ip_addr),
        environment=asset_dict.get("environment", "production"),
        criticality=asset_dict.get("criticality", AssetCriticality.TIER_1_PRODUCTION),
        exposure=asset_dict.get("exposure", NetworkExposure.INTERNAL_VPC),
        owner_team=asset_dict.get("owner_team", "SOC-Operations")
    )

    rule = data.get("rule", {})
    rule_id = rule.get("id", "5710")
    level = rule.get("level", 5)  # Wazuh levels 1-15
    desc = rule.get("description", "Wazuh security anomaly detected")
    full_log = data.get("full_log", desc)

    # Calculate CVSS proxy based on Wazuh rule level
    cvss = min(10.0, round(level * 0.7, 1))

    mitre = rule.get("mitre", {})
    tactic_list = mitre.get("tactic", [])
    technique_list = mitre.get("id", [])

    cwe = "CWE-307" if "brute" in desc.lower() else "CWE-284"

    vinfo = VulnerabilityInfo(
        cwe_id=cwe,
        title=f"EDR Alert [{rule_id}]: {desc}",
        description=f"Wazuh Event (Level {level}): {full_log}. MITRE Tactics: {', '.join(tactic_list) if tactic_list else 'Credential Access'}.",
        cvss_base_score=cvss,
        affected_resource=f"{hostname}::{data.get('location', '/var/log/secure')}",
        evidence={
            "wazuh_rule": rule,
            "mitre": mitre,
            "decoder": data.get("decoder", {}),
            "full_log": full_log
        }
    )

    alerts.append(UnifiedAlert(
        source=SensorSource.WAZUH_EDR,
        asset=asset,
        vulnerability=vinfo,
        raw_payload_hash=raw_hash
    ))

    return alerts
