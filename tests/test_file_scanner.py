"""
Tests for Industrial File & Code Security Scanner and Safe Patcher
"""
import os
import pytest
from scanner.file_scanner import file_security_scanner
from execution.file_patcher import safe_file_patcher
from schemas.code_scan import IssueSeverity, IssueCategory

def test_scan_vulnerable_python_file(tmp_path):
    test_file = tmp_path / "vulnerable_app.py"
    vulnerable_code = """import os
import pickle
import hashlib

AWS_KEY = "AKIA1234567890ABCDEF"

def run_user_cmd(cmd):
    # Insecure command execution
    os.system("ping " + cmd)

def load_session(cookie_data):
    # Insecure deserialization
    return pickle.loads(cookie_data)

def hash_password(pwd):
    # Weak hash
    return hashlib.md5(pwd.encode()).hexdigest()
"""
    test_file.write_text(vulnerable_code, encoding="utf-8")

    result = file_security_scanner.scan_file(str(test_file))

    assert result.has_critical is True
    assert result.total_lines > 10
    assert len(result.issues) >= 4

    # Verify rule IDs detected
    rule_ids = [i.rule_id for i in result.issues]
    assert "SEC-001" in rule_ids  # AWS Key
    assert "INJ-001" in rule_ids  # os.system
    assert "DES-001" in rule_ids  # pickle.loads
    assert "CRY-001" in rule_ids  # hashlib.md5

    # Verify secret is masked and never exposed in cleartext
    sec_issue = next(i for i in result.issues if i.rule_id == "SEC-001")
    assert "AKIA************CDEF" in sec_issue.vulnerable_code
    assert "AKIA1234567890ABCDEF" not in sec_issue.vulnerable_code

    # Verify remediation diff generation
    os_sys_issue = next(i for i in result.issues if i.rule_id == "INJ-001")
    assert os_sys_issue.remediation_diff is not None
    assert "--- a/vulnerable_app.py" in os_sys_issue.remediation_diff
    assert "+++ b/vulnerable_app.py" in os_sys_issue.remediation_diff

def test_scan_python_syntax_error(tmp_path):
    broken_file = tmp_path / "syntax_error.py"
    broken_file.write_text("def broken_func(\n    print('unclosed parenthesis'\n", encoding="utf-8")

    result = file_security_scanner.scan_file(str(broken_file))
    assert result.has_syntax_errors is True
    assert any(i.category == IssueCategory.SYNTAX_ERROR for i in result.issues)

def test_safe_file_patch_and_rollback(tmp_path):
    target = tmp_path / "service.py"
    original = """import os

def query(val):
    os.system("echo " + val)
"""
    target.write_text(original, encoding="utf-8")

    # Apply patch to line 4
    patch_res = safe_file_patcher.apply_patch(
        file_path=str(target),
        line_number=4,
        original_code='    os.system("echo " + val)',
        remediated_code='    import subprocess; subprocess.run(["echo", val], check=True)',
        approver="Lead SOC Architect",
        notes="Remediating command injection"
    )

    assert patch_res.success is True
    assert patch_res.syntax_valid is True
    assert patch_res.backup_path is not None
    assert os.path.exists(patch_res.backup_path)

    # Check patched file contents
    patched_content = target.read_text(encoding="utf-8")
    assert "subprocess.run" in patched_content
    assert "os.system" not in patched_content

    # Test Rollback
    rollback_ok, rollback_msg = safe_file_patcher.rollback(str(target), patch_res.backup_path)
    assert rollback_ok is True
    reverted_content = target.read_text(encoding="utf-8")
    assert "os.system" in reverted_content

def test_safe_file_patch_rejects_syntax_error(tmp_path):
    target = tmp_path / "valid.py"
    target.write_text("x = 10\nprint(x)\n", encoding="utf-8")

    # Attempt to apply a broken patch with unclosed string
    patch_res = safe_file_patcher.apply_patch(
        file_path=str(target),
        line_number=2,
        original_code="print(x)",
        remediated_code="print('broken unclosed string\n",
        approver="SecOps"
    )

    # Must reject patch and keep original code intact
    assert patch_res.success is False
    assert patch_res.syntax_valid is False
    assert "SyntaxError" in patch_res.message

    current_content = target.read_text(encoding="utf-8")
    assert current_content == "x = 10\nprint(x)\n"
