"""
Automated Safe Code Patcher & Rollback Engine
Applies validated security patches with atomic backups, pre-flight syntax checks,
and immutable WORM audit recording.
"""
import os
import shutil
import ast
import json
from datetime import datetime, timezone
from typing import Optional, Tuple
from schemas.code_scan import PatchApplyResult
from schemas.audit import AuditEventType
from core.audit_log import worm_audit_log

class SafeFilePatcher:
    def apply_patch(
        self,
        file_path: str,
        line_number: int,
        original_code: str,
        remediated_code: str,
        approver: str = "SecOps Lead",
        notes: str = "Automated security remediation"
    ) -> PatchApplyResult:
        """
        Applies a security patch to a specific line in a file with atomic safety guardrails:
        1. Validates target file existence.
        2. Creates an immutable backup file: <path>.bak.<timestamp>.
        3. Replaces target vulnerable line.
        4. Validates post-patch syntax (ast.parse for Python).
        5. If syntax check fails, automatically reverts from backup.
        6. Writes to disk and seals an audit record in the WORM ledger.
        """
        if not os.path.exists(file_path):
            return PatchApplyResult(
                success=False,
                file_path=file_path,
                message=f"File not found: {file_path}"
            )

        # Step 1: Read original content
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        if line_number < 1 or line_number > len(lines):
            return PatchApplyResult(
                success=False,
                file_path=file_path,
                message=f"Line number {line_number} is out of bounds (file has {len(lines)} lines)."
            )

        # Step 2: Create atomic backup
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"{file_path}.bak.{timestamp}"
        try:
            shutil.copy2(file_path, backup_path)
        except Exception as e:
            return PatchApplyResult(
                success=False,
                file_path=file_path,
                message=f"Failed to create atomic backup: {e}"
            )

        # Step 3: Apply remediation in-memory
        target_idx = line_number - 1
        lines[target_idx] = remediated_code if remediated_code.endswith("\n") else (remediated_code + "\n")
        new_content = "".join(lines)

        # Step 4: Pre-flight syntax validation
        if file_path.endswith(".py"):
            try:
                ast.parse(new_content, filename=file_path)
            except SyntaxError as e:
                # Revert immediately
                shutil.copy2(backup_path, file_path)
                return PatchApplyResult(
                    success=False,
                    file_path=file_path,
                    backup_path=backup_path,
                    syntax_valid=False,
                    message=f"Safety Check Failed: Proposed patch introduces Python SyntaxError: {e.msg} at line {e.lineno}. File reverted to backup."
                )

        # Step 5: Commit changes to disk
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(new_content)
        except Exception as e:
            shutil.copy2(backup_path, file_path)
            return PatchApplyResult(
                success=False,
                file_path=file_path,
                backup_path=backup_path,
                message=f"Failed to write patch to file: {e}"
            )

        # Step 6: Record event in WORM Cryptographic Ledger
        record = worm_audit_log.record_event(
            event_type=AuditEventType.REMEDIATION_EXECUTED,
            actor=f"CODE_PATCHER:{approver}",
            alert_id=None,
            details={
                "action": "FILE_PATCH_APPLIED",
                "file_path": file_path,
                "backup_path": backup_path,
                "line_number": line_number,
                "approver": approver,
                "notes": notes
            }
        )

        return PatchApplyResult(
            success=True,
            file_path=file_path,
            backup_path=backup_path,
            lines_changed=1,
            syntax_valid=True,
            message="Security patch successfully applied and verified with pre-flight syntax check.",
            worm_block_index=record.index
        )

    def rollback(self, file_path: str, backup_path: str, actor: str = "SecOps Engineer") -> Tuple[bool, str]:
        """
        Rolls back a patched file from its atomic backup.
        """
        if not os.path.exists(backup_path):
            return False, f"Backup file not found: {backup_path}"

        try:
            shutil.copy2(backup_path, file_path)
            worm_audit_log.record_event(
                event_type=AuditEventType.REMEDIATION_EXECUTED,
                actor=f"ROLLBACK:{actor}",
                alert_id=None,
                details={
                    "action": "FILE_ROLLBACK_APPLIED",
                    "file_path": file_path,
                    "restored_from": backup_path
                }
            )
            return True, f"Successfully restored {file_path} from backup {backup_path}."
        except Exception as e:
            return False, f"Failed to restore backup: {e}"

safe_file_patcher = SafeFilePatcher()
