"""
SonarQube SAST Ingestion Parser
Extracts static code analysis vulnerabilities, security hotspots, and CWE mappings
from SonarQube webhooks into canonical UnifiedAlert instances.
"""
import hashlib
import json
from typing import List, Dict, Any, Optional
from schemas.alerts import UnifiedAlert, SensorSource, AssetInfo, VulnerabilityInfo, AssetCriticality, NetworkExposure

SEVERITY_CVSS_MAP = {
    "BLOCKER": 9.2,
    "CRITICAL": 8.0,
    "MAJOR": 5.5,
    "MINOR": 3.0,
    "INFO": 1.0
}

def parse_sonarqube_alert(data: Dict[str, Any], asset_override: Optional[Dict[str, Any]] = None) -> List[UnifiedAlert]:
    """
    Parses a SonarQube webhook payload containing code security issues.
    """
    alerts: List[UnifiedAlert] = []
    project_name = data.get("project", {}).get("name") or data.get("serverUrl", "app-codebase")
    raw_hash = hashlib.sha256(json.dumps(data, sort_keys=True).encode("utf-8")).hexdigest()

    asset_dict = asset_override or {}
    asset = AssetInfo(
        hostname=asset_dict.get("hostname", f"repo-{project_name}"),
        ip_address=asset_dict.get("ip_address", "10.0.8.21"),
        environment=asset_dict.get("environment", "production"),
        criticality=asset_dict.get("criticality", AssetCriticality.TIER_0_MISSION_CRITICAL),
        exposure=asset_dict.get("exposure", NetworkExposure.PUBLIC_INTERNET),
        owner_team=asset_dict.get("owner_team", "Backend-Engineering")
    )

    # SonarQube webhooks may contain an issue or qualityGate payload
    issue = data.get("issue")
    issues = [issue] if issue else data.get("issues", [])

    if not issues and "qualityGate" in data:
        # Generate alert from failed security quality gate
        qg = data["qualityGate"]
        vinfo = VulnerabilityInfo(
            cwe_id="CWE-1026",
            title=f"SonarQube Security Quality Gate Failed: {qg.get('status')}",
            description=f"Project {project_name} failed security gate with {len(qg.get('conditions', []))} condition breaches.",
            cvss_base_score=7.8,
            affected_resource=project_name
        )
        alerts.append(UnifiedAlert(
            source=SensorSource.SONARQUBE,
            asset=asset,
            vulnerability=vinfo,
            raw_payload_hash=raw_hash
        ))
        return alerts

    for iss in issues:
        rule = iss.get("rule", "security:general")
        msg = iss.get("message", "Detected security vulnerability in codebase")
        severity_str = iss.get("severity", "MAJOR").upper()
        cvss = SEVERITY_CVSS_MAP.get(severity_str, 5.0)
        component = iss.get("component", "src/main.py")
        line = iss.get("line", 1)

        cwe = "CWE-89" if "sql" in msg.lower() else ("CWE-79" if "xss" in msg.lower() else "CWE-20")

        vinfo = VulnerabilityInfo(
            cwe_id=cwe,
            title=f"SAST: {msg}",
            description=f"SonarQube Rule {rule} triggered at {component}:{line}. Severity: {severity_str}.",
            cvss_base_score=cvss,
            affected_resource=f"{component}:{line}",
            evidence=iss
        )

        alert = UnifiedAlert(
            source=SensorSource.SONARQUBE,
            asset=asset,
            vulnerability=vinfo,
            raw_payload_hash=raw_hash
        )
        alerts.append(alert)

    return alerts
