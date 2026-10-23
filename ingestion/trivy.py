"""
Trivy Ingestion Parser
Extracts container and filesystem vulnerabilities from Trivy JSON reports
and maps them into canonical UnifiedAlert instances.
"""
import hashlib
import json
from typing import List, Dict, Any, Optional
from schemas.alerts import UnifiedAlert, SensorSource, AssetInfo, VulnerabilityInfo, AssetCriticality, NetworkExposure

def parse_trivy_report(data: Dict[str, Any], asset_override: Optional[Dict[str, Any]] = None) -> List[UnifiedAlert]:
    """
    Parses a Trivy vulnerability scan payload into UnifiedAlert models.
    """
    alerts: List[UnifiedAlert] = []
    artifact_name = data.get("ArtifactName", "unknown-container:latest")
    raw_hash = hashlib.sha256(json.dumps(data, sort_keys=True).encode("utf-8")).hexdigest()

    # Default asset info or override
    asset_dict = asset_override or {}
    asset = AssetInfo(
        hostname=asset_dict.get("hostname", artifact_name.split(":")[0]),
        ip_address=asset_dict.get("ip_address", "10.0.12.44"),
        environment=asset_dict.get("environment", "production"),
        criticality=asset_dict.get("criticality", AssetCriticality.TIER_1_PRODUCTION),
        exposure=asset_dict.get("exposure", NetworkExposure.PUBLIC_INTERNET),
        owner_team=asset_dict.get("owner_team", "AppSec-Team")
    )

    results = data.get("Results", [])
    for res in results:
        target = res.get("Target", artifact_name)
        vulnerabilities = res.get("Vulnerabilities", [])
        
        for vuln in vulnerabilities:
            cve_id = vuln.get("VulnerabilityID")
            pkg_name = vuln.get("PkgName")
            installed_ver = vuln.get("InstalledVersion")
            fixed_ver = vuln.get("FixedVersion")
            title = vuln.get("Title") or f"Vulnerability in {pkg_name}"
            desc = vuln.get("Description", "No description provided by Trivy.")
            
            # Extract CVSS score
            cvss_data = vuln.get("CVSS", {})
            cvss_score = 0.0
            cvss_vector = None
            if "nvd" in cvss_data:
                cvss_score = float(cvss_data["nvd"].get("V3Score", 0.0))
                cvss_vector = cvss_data["nvd"].get("V3Vector")
            elif "redhat" in cvss_data:
                cvss_score = float(cvss_data["redhat"].get("V3Score", 0.0))
                cvss_vector = cvss_data["redhat"].get("V3Vector")

            # Check known critical CVEs (like Log4j or XZ) for CISA KEV default
            is_kev = False
            if cve_id in ["CVE-2024-3094", "CVE-2021-44228", "CVE-2023-4863", "CVE-2023-38606", "CVE-2023-22515"]:
                is_kev = True

            vinfo = VulnerabilityInfo(
                cve_id=cve_id,
                title=title,
                description=desc,
                cvss_base_score=cvss_score,
                cvss_vector=cvss_vector,
                cisa_kev_active=is_kev,
                package_name=pkg_name,
                installed_version=installed_ver,
                fixed_version=fixed_ver,
                affected_resource=f"{target}::{pkg_name}",
                evidence=vuln
            )

            alert = UnifiedAlert(
                source=SensorSource.TRIVY,
                asset=asset,
                vulnerability=vinfo,
                raw_payload_hash=raw_hash
            )
            alerts.append(alert)

    return alerts
