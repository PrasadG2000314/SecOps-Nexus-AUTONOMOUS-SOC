"""
Industrial File & Directory Security Scanner
Discovers vulnerabilities across codebases, generates unified diff patches,
and correlates findings with SecOps-Nexus risk scoring and audit trails.
"""
import os
import difflib
from typing import List, Optional
from datetime import datetime, timezone

from schemas.code_scan import (
    CodeVulnerabilityIssue,
    FileScanResult,
    DirectoryScanResult,
    IssueSeverity,
    IssueCategory
)
from schemas.alerts import UnifiedAlert, SensorSource, AssetInfo, VulnerabilityInfo, AssetCriticality, NetworkExposure
from scanner.rules import SECURITY_RULES
from scanner.ast_analyzer import PythonAstSecurityAnalyzer
from core.audit_log import worm_audit_log
from core.security import mask_secret, redact_sensitive_text
from schemas.audit import AuditEventType

IGNORED_DIRS = {
    ".git", ".svn", "node_modules", "venv", ".venv", "env",
    "__pycache__", ".pytest_cache", ".idea", ".vscode", "dist", "build"
}

IGNORED_EXTENSIONS = {
    ".pyc", ".pyo", ".exe", ".dll", ".so", ".dylib", ".bin",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".zip", ".tar", ".gz", ".7z", ".pdf", ".mp4", ".woff", ".woff2"
}

class FileSecurityScanner:
    def __init__(self):
        self.ast_analyzer = PythonAstSecurityAnalyzer()

    def scan_file(self, file_path: str) -> FileScanResult:
        """
        Scans a single file on disk for syntax bugs, security flaws, and exposed credentials.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception as e:
            raise IOError(f"Could not read file {file_path}: {e}")

        lines = content.splitlines()
        issues: List[CodeVulnerabilityIssue] = []

        # 1. Python AST Deep Analysis
        if file_path.endswith(".py"):
            ast_issues, _ = self.ast_analyzer.analyze_source(content, file_path)
            for iss in ast_issues:
                iss.remediation_diff = self._generate_diff(lines, iss.line_number, iss.recommended_fix, file_name)
                issues.append(iss)

        # 2. Pattern Matching against Security Rules
        self._scan_with_regex_rules(content, lines, file_path, file_name, issues)

        # Calculate metrics
        has_critical = any(i.severity == IssueSeverity.CRITICAL for i in issues)
        has_syntax = any(i.category == IssueCategory.SYNTAX_ERROR for i in issues)
        max_cvss = max([i.cvss_score for i in issues], default=0.0)
        risk_score = round(min(100.0, max_cvss * 10.0), 1)

        result = FileScanResult(
            file_path=os.path.abspath(file_path),
            file_name=file_name,
            file_size_bytes=file_size,
            total_lines=len(lines),
            scanned_at=datetime.now(timezone.utc),
            issues=issues,
            has_critical=has_critical,
            has_syntax_errors=has_syntax,
            risk_score=risk_score
        )

        # Record in WORM Cryptographic Ledger
        worm_audit_log.record_event(
            event_type=AuditEventType.ALERT_INGESTED,
            actor="FILE_SECURITY_SCANNER",
            alert_id=None,
            details={
                "file_path": file_path,
                "issues_found": len(issues),
                "has_critical": has_critical,
                "risk_score": risk_score
            }
        )

        return result

    def scan_directory(self, dir_path: str, max_files: int = 500) -> DirectoryScanResult:
        """
        Recursively scans an entire codebase or project directory.
        """
        if not os.path.exists(dir_path):
            raise FileNotFoundError(f"Directory not found: {dir_path}")

        start_time = datetime.now()
        scanned_results: List[FileScanResult] = []
        file_count = 0

        for root, dirs, files in os.walk(dir_path):
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and not d.startswith(".")]

            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in IGNORED_EXTENSIONS or file.endswith(".bak"):
                    continue

                full_path = os.path.join(root, file)
                try:
                    res = self.scan_file(full_path)
                    scanned_results.append(res)
                    file_count += 1
                    if file_count >= max_files:
                        break
                except Exception as e:
                    print(f"[SCANNER] Skipping {full_path}: {e}")

            if file_count >= max_files:
                break

        duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)

        total_issues = sum(len(r.issues) for r in scanned_results)
        critical_count = sum(sum(1 for i in r.issues if i.severity == IssueSeverity.CRITICAL) for r in scanned_results)
        high_count = sum(sum(1 for i in r.issues if i.severity == IssueSeverity.HIGH) for r in scanned_results)
        medium_count = sum(sum(1 for i in r.issues if i.severity == IssueSeverity.MEDIUM) for r in scanned_results)
        low_count = sum(sum(1 for i in r.issues if i.severity in (IssueSeverity.LOW, IssueSeverity.INFO)) for r in scanned_results)

        return DirectoryScanResult(
            root_path=os.path.abspath(dir_path),
            files_scanned=file_count,
            total_issues=total_issues,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            scan_duration_ms=duration_ms,
            file_results=scanned_results
        )

    def _scan_with_regex_rules(self, content: str, lines: List[str], file_path: str, file_name: str, issues: List[CodeVulnerabilityIssue]):
        existing_rule_lines = {(i.rule_id, i.line_number) for i in issues}

        for rule in SECURITY_RULES:
            for match in rule.pattern.finditer(content):
                # Calculate 1-indexed line number from match start
                start_idx = match.start()
                line_no = content.count("\n", 0, start_idx) + 1
                col_no = start_idx - content.rfind("\n", 0, start_idx)

                # Avoid duplicate report if AST already caught it on the same line
                if (rule.rule_id, line_no) in existing_rule_lines:
                    continue

                matched_line = lines[line_no - 1] if line_no <= len(lines) else match.group(0)

                # Formulate intelligent fix suggestion
                fix_code = rule.fix_replacement or "# Refactor vulnerable line"
                display_vulnerable_code = matched_line.strip()

                if rule.category == IssueCategory.SECRETS:
                    raw_secret = match.group(2) if len(match.groups()) >= 2 else match.group(0)
                    masked = mask_secret(raw_secret, visible_prefix=4, visible_suffix=4)
                    display_vulnerable_code = matched_line.replace(raw_secret, masked).strip()
                    fix_code = matched_line.replace(raw_secret, rule.fix_replacement or "os.getenv('SECRET_KEY')")
                elif rule.category == IssueCategory.INJECTION and "os.system" in matched_line:
                    fix_code = matched_line.replace("os.system(", "subprocess.run([") + ", check=True)"

                diff = self._generate_diff(lines, line_no, fix_code, file_name)
                if rule.category == IssueCategory.SECRETS:
                    diff = redact_sensitive_text(diff)

                issues.append(CodeVulnerabilityIssue(
                    rule_id=rule.rule_id,
                    category=rule.category,
                    severity=rule.severity,
                    cwe_id=rule.cwe_id,
                    title=rule.title,
                    description=rule.description,
                    file_path=file_path,
                    line_number=line_no,
                    column_number=col_no,
                    vulnerable_code=display_vulnerable_code,
                    recommended_fix=fix_code.strip(),
                    remediation_diff=diff,
                    cvss_score=rule.cvss
                ))
                existing_rule_lines.add((rule.rule_id, line_no))

    def _generate_diff(self, lines: List[str], line_no: int, replacement_line: str, file_name: str) -> str:
        """Generates unified git diff snippet for the proposed patch."""
        orig_line = lines[line_no - 1] if line_no <= len(lines) else ""
        from_lines = [orig_line + "\n"]
        to_lines = [replacement_line + "\n"]

        diff = difflib.unified_diff(
            from_lines,
            to_lines,
            fromfile=f"a/{file_name}",
            tofile=f"b/{file_name}",
            lineterm="\n"
        )
        return "".join(diff)

file_security_scanner = FileSecurityScanner()
