"""
Alert Deduplication & Correlation Engine
Prevents alert fatigue by generating canonical fingerprints for incoming sensor alerts
and correlating duplicates across different scanners (e.g. Trivy vs Wazuh).
"""
import hashlib
from typing import Dict, Optional, Tuple
from datetime import datetime, timezone
from schemas.alerts import UnifiedAlert

class AlertDeduplicator:
    def __init__(self):
        # Key: fingerprint -> (existing_alert, count, first_seen, last_seen)
        self._cache: Dict[str, Tuple[UnifiedAlert, int, datetime, datetime]] = {}

    def compute_fingerprint(self, alert: UnifiedAlert) -> str:
        """
        Creates a deterministic fingerprint combining:
        - Target host / asset identifier
        - Vulnerability identity (CVE ID or normalized title)
        - Affected resource (package or port)
        """
        cve_or_vuln = (alert.vulnerability.cve_id or alert.vulnerability.title).strip().lower()
        host = alert.asset.hostname.strip().lower()
        resource = (alert.vulnerability.affected_resource or alert.vulnerability.package_name or "global").strip().lower()

        raw_key = f"{host}::{cve_or_vuln}::{resource}"
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    def process(self, alert: UnifiedAlert) -> Tuple[bool, UnifiedAlert, int]:
        """
        Checks if the alert is a duplicate.
        Returns:
            (is_duplicate, canonical_alert, occurrence_count)
        """
        fingerprint = self.compute_fingerprint(alert)
        alert.deduplication_fingerprint = fingerprint
        now = datetime.now(timezone.utc)

        if fingerprint in self._cache:
            existing_alert, count, first_seen, _ = self._cache[fingerprint]
            new_count = count + 1
            self._cache[fingerprint] = (existing_alert, new_count, first_seen, now)
            # Update latest evidence or risk if changed
            return True, existing_alert, new_count
        else:
            self._cache[fingerprint] = (alert, 1, now, now)
            return False, alert, 1

    def clear(self):
        """Clears in-memory deduplication cache."""
        self._cache.clear()

alert_deduplicator = AlertDeduplicator()
