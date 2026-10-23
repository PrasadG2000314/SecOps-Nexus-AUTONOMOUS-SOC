"""
Pydantic Schemas for Real Code & File Security Analysis and Auto-Fixing
"""
from enum import Enum
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field

class IssueSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class IssueCategory(str, Enum):
    INJECTION = "INJECTION"               # SQLi, Command Injection, OS RCE
    SECRETS = "SECRETS"                   # Hardcoded API keys, tokens, passwords
    INSECURE_DESERIALIZATION = "INSECURE_DESERIALIZATION" # pickle, yaml.load
    CRYPTO = "CRYPTO"                     # Weak hashing (MD5/SHA1), weak ciphers
    PATH_TRAVERSAL = "PATH_TRAVERSAL"     # ../ directory traversal
    MISCONFIGURATION = "MISCONFIGURATION" # Insecure Dockerfile, CORS wildcard, debug=True
    SYNTAX_ERROR = "SYNTAX_ERROR"         # Unparseable code or fatal bugs

class CodeVulnerabilityIssue(BaseModel):
    id: str = Field(default_factory=lambda: f"ISSUE-{datetime.now().strftime('%M%S%f')[:8]}")
    rule_id: str
    category: IssueCategory
    severity: IssueSeverity
    cwe_id: Optional[str] = None
    title: str
    description: str
    file_path: str
    line_number: int
    column_number: Optional[int] = 1
    vulnerable_code: str
    recommended_fix: str
    remediation_diff: Optional[str] = None
    cvss_score: float = 5.0

class FileScanResult(BaseModel):
    file_path: str
    file_name: str
    file_size_bytes: int
    total_lines: int
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    issues: List[CodeVulnerabilityIssue] = Field(default_factory=list)
    has_critical: bool = False
    has_syntax_errors: bool = False
    risk_score: float = 0.0

class DirectoryScanResult(BaseModel):
    root_path: str
    files_scanned: int
    total_issues: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    scan_duration_ms: int
    file_results: List[FileScanResult] = Field(default_factory=list)

class PatchRequest(BaseModel):
    file_path: str
    issue_id: str
    patch_diff: str
    approver_name: str = "SecOps Lead"
    approver_role: str = "Principal Security Engineer"
    notes: Optional[str] = "Approved automated code remediation."

class PatchApplyResult(BaseModel):
    success: bool
    file_path: str
    backup_path: Optional[str] = None
    lines_changed: int = 0
    syntax_valid: bool = True
    message: str
    applied_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    worm_block_index: Optional[int] = None
