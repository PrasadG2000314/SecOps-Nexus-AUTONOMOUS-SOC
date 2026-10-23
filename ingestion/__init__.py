"""
Ingestion Parsers for Security Scanners and Sensors
"""
from .trivy import parse_trivy_report
from .sonarqube import parse_sonarqube_alert
from .nmap import parse_nmap_scan
from .wazuh import parse_wazuh_event

__all__ = [
    "parse_trivy_report",
    "parse_sonarqube_alert",
    "parse_nmap_scan",
    "parse_wazuh_event"
]
