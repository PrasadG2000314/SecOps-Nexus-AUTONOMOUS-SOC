"""
WORM (Write Once Read Many) Cryptographic Audit Log
An append-only, tamper-evident hash-chained ledger that ensures Zero-Trust auditability.
Every scan, reasoning step, HITL click, and execution is sealed in a Merkle/SHA-256 chain.
"""
import json
import hashlib
import os
import threading
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from schemas.audit import AuditRecord, AuditEventType, AuditChainVerificationResult

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
AUDIT_LOG_FILE = "audit_ledger.jsonl"

class CryptographicWormAuditLog:
    def __init__(self, storage_path: str = AUDIT_LOG_FILE):
        self.storage_path = storage_path
        self._lock = threading.Lock()
        self.records: List[AuditRecord] = []
        self._load_or_initialize()

    def _load_or_initialize(self):
        """Loads existing chain from disk or creates the genesis block."""
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            record_dict = json.loads(line)
                            record = AuditRecord(**record_dict)
                            self.records.append(record)
            except Exception as e:
                print(f"[AUDIT] Warning: Error loading audit log: {e}")

        if not self.records:
            # Create Genesis Block
            genesis = self._create_block(
                event_type=AuditEventType.SYSTEM_BOOT,
                actor="SYSTEM_INITIALIZER",
                alert_id=None,
                details={"message": "SecOps-Nexus WORM Cryptographic Ledger Initialized", "version": "1.0.0"},
                previous_hash=GENESIS_HASH
            )
            self.records.append(genesis)
            self._persist_record(genesis)

    def _compute_hash(self, index: int, timestamp: str, event_type: str, actor: str,
                      alert_id: Optional[str], details: Dict[str, Any], payload_sha256: str,
                      previous_hash: str) -> str:
        """Computes deterministic SHA-256 hash for a block."""
        canonical_content = json.dumps({
            "index": index,
            "timestamp": timestamp,
            "event_type": event_type,
            "actor": actor,
            "alert_id": alert_id,
            "details": details,
            "payload_sha256": payload_sha256,
            "previous_hash": previous_hash
        }, sort_keys=True)
        return hashlib.sha256(canonical_content.encode("utf-8")).hexdigest()

    def _create_block(self, event_type: Any, actor: str, alert_id: Optional[str],
                      details: Dict[str, Any], previous_hash: str) -> AuditRecord:
        """Helper to create and hash a new audit record block."""
        index = len(self.records)
        now = datetime.now(timezone.utc)
        iso_time = now.isoformat()
        
        event_type_val = event_type.value if hasattr(event_type, "value") else str(event_type)
        enum_type = AuditEventType(event_type_val) if event_type_val in [e.value for e in AuditEventType] else AuditEventType.SYSTEM_BOOT

        details_bytes = json.dumps(details, sort_keys=True).encode("utf-8")
        payload_sha256 = hashlib.sha256(details_bytes).hexdigest()

        current_hash = self._compute_hash(
            index=index,
            timestamp=iso_time,
            event_type=event_type_val,
            actor=actor,
            alert_id=alert_id,
            details=details,
            payload_sha256=payload_sha256,
            previous_hash=previous_hash
        )

        return AuditRecord(
            index=index,
            timestamp=now,
            event_type=enum_type,
            actor=actor,
            alert_id=alert_id,
            details=details,
            payload_sha256=payload_sha256,
            previous_hash=previous_hash,
            current_hash=current_hash
        )

    def _persist_record(self, record: AuditRecord):
        """Appends record to the disk storage in an append-only fashion."""
        try:
            with open(self.storage_path, "a", encoding="utf-8") as f:
                f.write(record.model_dump_json() + "\n")
        except Exception as e:
            print(f"[AUDIT] Critical: Failed to persist audit record: {e}")

    def record_event(self, event_type: AuditEventType, actor: str,
                     alert_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None) -> AuditRecord:
        """Records and cryptographically seals a new event in the ledger."""
        with self._lock:
            prev_hash = self.records[-1].current_hash if self.records else GENESIS_HASH
            new_block = self._create_block(
                event_type=event_type,
                actor=actor,
                alert_id=alert_id,
                details=details or {},
                previous_hash=prev_hash
            )
            self.records.append(new_block)
            self._persist_record(new_block)
            return new_block

    def verify_chain_integrity(self) -> AuditChainVerificationResult:
        """
        Validates the entire chain from genesis block to the tip.
        Detects any tampering, alteration, or block deletion.
        """
        with self._lock:
            if not self.records:
                return AuditChainVerificationResult(
                    is_valid=False,
                    total_records=0,
                    genesis_hash=GENESIS_HASH,
                    latest_hash="",
                    message="Audit ledger is empty."
                )

            for i, record in enumerate(self.records):
                # Verify link to previous block
                if i == 0:
                    if record.previous_hash != GENESIS_HASH:
                        return AuditChainVerificationResult(
                            is_valid=False,
                            total_records=len(self.records),
                            genesis_hash=record.current_hash,
                            latest_hash=self.records[-1].current_hash,
                            broken_link_index=0,
                            message="Genesis block previous_hash is invalid."
                        )
                else:
                    prev_record = self.records[i - 1]
                    if record.previous_hash != prev_record.current_hash:
                        return AuditChainVerificationResult(
                            is_valid=False,
                            total_records=len(self.records),
                            genesis_hash=self.records[0].current_hash,
                            latest_hash=self.records[-1].current_hash,
                            broken_link_index=i,
                            message=f"Broken hash chain at block index {i}: previous_hash mismatch."
                        )

                # Recompute current block hash
                details_bytes = json.dumps(record.details, sort_keys=True).encode("utf-8")
                computed_payload_hash = hashlib.sha256(details_bytes).hexdigest()
                if computed_payload_hash != record.payload_sha256:
                    return AuditChainVerificationResult(
                        is_valid=False,
                        total_records=len(self.records),
                        genesis_hash=self.records[0].current_hash,
                        latest_hash=self.records[-1].current_hash,
                        broken_link_index=i,
                        message=f"Tampered payload detected inside block index {i}!"
                    )

                recomputed_hash = self._compute_hash(
                    index=record.index,
                    timestamp=record.timestamp.isoformat(),
                    event_type=record.event_type.value,
                    actor=record.actor,
                    alert_id=record.alert_id,
                    details=record.details,
                    payload_sha256=record.payload_sha256,
                    previous_hash=record.previous_hash
                )

                if recomputed_hash != record.current_hash:
                    return AuditChainVerificationResult(
                        is_valid=False,
                        total_records=len(self.records),
                        genesis_hash=self.records[0].current_hash,
                        latest_hash=self.records[-1].current_hash,
                        broken_link_index=i,
                        message=f"Tampered block hash at index {i}!"
                    )

            return AuditChainVerificationResult(
                is_valid=True,
                total_records=len(self.records),
                genesis_hash=self.records[0].current_hash,
                latest_hash=self.records[-1].current_hash,
                message="WORM Audit Ledger Integrity Verified: All cryptographic links intact."
            )

    def get_recent_records(self, limit: int = 50) -> List[AuditRecord]:
        """Returns the most recent audit records in reverse chronological order."""
        with self._lock:
            return list(reversed(self.records[-limit:]))

# Global Singleton Instance
worm_audit_log = CryptographicWormAuditLog()
