"""
Nmap Network Perimeter Scanner Ingestion Parser
Maps exposed ports, insecure daemon banners, and NSE vulnerability scripts
into canonical UnifiedAlert instances.
"""
import hashlib
import json
from typing import List, Dict, Any, Optional
from schemas.alerts import UnifiedAlert, SensorSource, AssetInfo, VulnerabilityInfo, AssetCriticality, NetworkExposure

def parse_nmap_scan(data: Dict[str, Any], asset_override: Optional[Dict[str, Any]] = None) -> List[UnifiedAlert]:
    alerts: List[UnifiedAlert] = []
    raw_hash = hashlib.sha256(json.dumps(data, sort_keys=True).encode("utf-8")).hexdigest()

    host_ip = data.get("ip", "198.51.100.25")
    hostname = data.get("hostname", f"srv-{host_ip.replace('.', '-')}")

    asset_dict = asset_override or {}
    asset = AssetInfo(
        hostname=asset_dict.get("hostname", hostname),
        ip_address=asset_dict.get("ip_address", host_ip),
        environment=asset_dict.get("environment", "production"),
        criticality=asset_dict.get("criticality", AssetCriticality.TIER_1_PRODUCTION),
        exposure=asset_dict.get("exposure", NetworkExposure.PUBLIC_INTERNET),
        owner_team=asset_dict.get("owner_team", "Network-Sec")
    )

    ports = data.get("ports", [])
    for p in ports:
        port_num = p.get("port")
        service = p.get("service", "unknown")
        state = p.get("state", "open")
        scripts = p.get("scripts", [])

        if state != "open":
            continue

        # Insecure or high-risk exposed services
        high_risk_ports = {
            21: ("FTP Exposed Unencrypted", 7.5, "CWE-319"),
            23: ("Telnet Exposed in Cleartext", 8.5, "CWE-319"),
            3389: ("RDP Port Publicly Exposed to Internet", 7.8, "CWE-284"),
            6379: ("Redis Port Exposed Without Authentication", 9.8, "CWE-306"),
            9200: ("Elasticsearch Cluster Exposed to Public Internet", 8.8, "CWE-306")
        }

        if port_num in high_risk_ports:
            title, cvss, cwe = high_risk_ports[port_num]
            vinfo = VulnerabilityInfo(
                cwe_id=cwe,
                title=f"Network: {title} on port {port_num}",
                description=f"Nmap discovered {service} running on open port {port_num} on public asset {host_ip}. Vulnerable to remote access or brute-force.",
                cvss_base_score=cvss,
                affected_resource=f"{host_ip}:{port_num}",
                evidence=p
            )
            alerts.append(UnifiedAlert(
                source=SensorSource.NMAP,
                asset=asset,
                vulnerability=vinfo,
                raw_payload_hash=raw_hash
            ))

        # Check NSE script vulnerability reports
        for scr in scripts:
            if scr.get("is_vulnerable"):
                vinfo = VulnerabilityInfo(
                    cve_id=scr.get("cve"),
                    title=f"Nmap NSE: {scr.get('name', 'Vulnerability detected')}",
                    description=scr.get("output", "Exploitable condition verified via NSE probe."),
                    cvss_base_score=float(scr.get("cvss", 8.0)),
                    cisa_kev_active=scr.get("in_kev", False),
                    affected_resource=f"{host_ip}:{port_num}",
                    evidence=scr
                )
                alerts.append(UnifiedAlert(
                    source=SensorSource.NMAP,
                    asset=asset,
                    vulnerability=vinfo,
                    raw_payload_hash=raw_hash
                ))

    return alerts
