"""
Unified Security Alert & Ingestion Schemas
Normalizes alerts across Trivy, SonarQube, Nmap, Wazuh/EDR, and PAM audit logs.
"""
from enum import Enum
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from pydantic import BaseModel, Field
import uuid

class SensorSource(str, Enum):
    TRIVY = "TRIVY"
    SONARQUBE = "SONARQUBE"
    NMAP = "NMAP"
    WAZUH_EDR = "WAZUH_EDR"
    PAM_AUDIT = "PAM_AUDIT"
    SIMULATOR = "SIMULATOR"

class AssetCriticality(str, Enum):
    TIER_0_MISSION_CRITICAL = "TIER_0_MISSION_CRITICAL"  # Prod Databases, K8s Control Plane, IAM
    TIER_1_PRODUCTION = "TIER_1_PRODUCTION"              # Production Customer-facing microservices
    TIER_2_STAGING = "TIER_2_STAGING"                    # Staging / Pre-prod clusters
    TIER_3_INTERNAL_DEV = "TIER_3_INTERNAL_DEV"          # Dev sandboxes, CI/CD runners

class NetworkExposure(str, Enum):
    PUBLIC_INTERNET = "PUBLIC_INTERNET"                  # Exposed directly via ingress / public IP
    INTERNAL_VPC = "INTERNAL_VPC"                        # Internal VPC / Private Subnet
    AIR_GAPPED = "AIR_GAPPED"                            # Strictly isolated management network

class AlertStatus(str, Enum):
    INGESTED = "INGESTED"
    ANALYZING = "ANALYZING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    AUTO_CONTAINED = "AUTO_CONTAINED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTING = "EXECUTING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"

class AssetInfo(BaseModel):
    hostname: str
    ip_address: Optional[str] = "10.0.4.15"
    environment: str = "production"
    criticality: AssetCriticality = AssetCriticality.TIER_1_PRODUCTION
    exposure: NetworkExposure = NetworkExposure.PUBLIC_INTERNET
    owner_team: str = "SecOps-Platform"

class VulnerabilityInfo(BaseModel):
    cve_id: Optional[str] = None                         # e.g., "CVE-2024-3094"
    cwe_id: Optional[str] = None                         # e.g., "CWE-89" (SQL Injection)
    title: str
    description: str
    cvss_base_score: float = Field(default=0.0, ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None
    cisa_kev_active: bool = False                        # In CISA Known Exploited Vulnerabilities catalog
    package_name: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    affected_resource: Optional[str] = None             # File path, container image, or port
    evidence: Optional[Dict[str, Any]] = None

class UnifiedAlert(BaseModel):
    id: str = Field(default_factory=lambda: f"ALT-{uuid.uuid4().hex[:8].upper()}")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: SensorSource
    asset: AssetInfo
    vulnerability: VulnerabilityInfo
    raw_payload_hash: str                               # SHA-256 hash of original webhook payload
    contextual_risk_score: float = 0.0                   # Calculated by Core Risk Engine (0-100)
    severity_level: str = "MEDIUM"                       # CRITICAL, HIGH, MEDIUM, LOW
    status: AlertStatus = AlertStatus.INGESTED
    deduplication_fingerprint: str = ""
    status_updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AlertIngestRequest(BaseModel):
    source: SensorSource
    raw_data: Dict[str, Any]
    asset_override: Optional[Dict[str, Any]] = None
