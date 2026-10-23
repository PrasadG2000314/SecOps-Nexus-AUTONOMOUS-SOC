"""
Python AST (Abstract Syntax Tree) Deep Security Analyzer
Performs semantic analysis to detect syntax errors, injection bugs, and insecure function calls.
"""
import ast
from typing import List, Tuple, Optional
from schemas.code_scan import CodeVulnerabilityIssue, IssueCategory, IssueSeverity

class PythonAstSecurityAnalyzer:
    def analyze_source(self, source_code: str, file_path: str) -> Tuple[List[CodeVulnerabilityIssue], Optional[str]]:
        """
        Parses source code into an AST and analyzes semantic security constructs.
        Returns: (issues_list, syntax_error_msg_if_any)
        """
        issues: List[CodeVulnerabilityIssue] = []
        lines = source_code.splitlines()

        # Step 1: Check for Fatal Syntax Errors
        try:
            tree = ast.parse(source_code, filename=file_path)
        except SyntaxError as e:
            line_no = e.lineno or 1
            col_no = e.offset or 1
            err_line = lines[line_no - 1] if line_no <= len(lines) else ""
            issues.append(CodeVulnerabilityIssue(
                rule_id="SYN-001",
                category=IssueCategory.SYNTAX_ERROR,
                severity=IssueSeverity.HIGH,
                cwe_id="CWE-1164",
                title=f"Python Syntax Error: {e.msg}",
                description=f"File contains invalid syntax at line {line_no}, column {col_no}: '{e.msg}'. Code cannot execute.",
                file_path=file_path,
                line_number=line_no,
                column_number=col_no,
                vulnerable_code=err_line,
                recommended_fix="# Fix syntax syntax around this line",
                cvss_score=7.0
            ))
            return issues, str(e)

        # Step 2: Walk AST Nodes to Detect Insecure Constructs
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                self._check_call_node(node, lines, file_path, issues)

        return issues, None

    def _check_call_node(self, node: ast.Call, lines: List[str], file_path: str, issues: List[CodeVulnerabilityIssue]):
        func_name = self._get_call_name(node.func)
        line_no = getattr(node, "lineno", 1)
        code_line = lines[line_no - 1] if line_no <= len(lines) else ""

        # 1. eval() or exec()
        if func_name in ("eval", "exec"):
            issues.append(CodeVulnerabilityIssue(
                rule_id="INJ-003",
                category=IssueCategory.INJECTION,
                severity=IssueSeverity.CRITICAL,
                cwe_id="CWE-95",
                title=f"Dangerous Dynamic Code Evaluation: {func_name}()",
                description=f"Execution of dynamic string via {func_name}() allows remote code execution if input is not strictly controlled.",
                file_path=file_path,
                line_number=line_no,
                column_number=getattr(node, "col_offset", 1),
                vulnerable_code=code_line,
                recommended_fix="ast.literal_eval" if func_name == "eval" else "# Refactor to avoid dynamic exec()",
                cvss_score=9.8
            ))

        # 2. os.system() or os.popen()
        elif func_name in ("os.system", "os.popen"):
            issues.append(CodeVulnerabilityIssue(
                rule_id="INJ-001",
                category=IssueCategory.INJECTION,
                severity=IssueSeverity.CRITICAL,
                cwe_id="CWE-78",
                title=f"Command Injection Vector: {func_name}()",
                description=f"{func_name}() runs untrusted shell strings directly. Vulnerable to shell metacharacter injection (e.g. ';', '&&').",
                file_path=file_path,
                line_number=line_no,
                column_number=getattr(node, "col_offset", 1),
                vulnerable_code=code_line,
                recommended_fix="subprocess.run(['command', arg], check=True)",
                cvss_score=9.8
            ))

        # 3. subprocess with shell=True
        elif func_name.startswith("subprocess."):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    issues.append(CodeVulnerabilityIssue(
                        rule_id="INJ-002",
                        category=IssueCategory.INJECTION,
                        severity=IssueSeverity.CRITICAL,
                        cwe_id="CWE-78",
                        title="Subprocess Executed with shell=True",
                        description="Spawning a subshell with shell=True bypasses command argument isolation and invites shell injection.",
                        file_path=file_path,
                        line_number=line_no,
                        column_number=getattr(node, "col_offset", 1),
                        vulnerable_code=code_line,
                        recommended_fix=code_line.replace("shell=True", "shell=False"),
                        cvss_score=9.0
                    ))

        # 4. pickle.loads() or pickle.load()
        elif func_name in ("pickle.loads", "pickle.load", "_pickle.loads"):
            issues.append(CodeVulnerabilityIssue(
                rule_id="DES-001",
                category=IssueCategory.INSECURE_DESERIALIZATION,
                severity=IssueSeverity.CRITICAL,
                cwe_id="CWE-502",
                title="Insecure Deserialization via pickle",
                description="pickle is inherently unauthenticated and permits arbitrary Python object execution during unpickling.",
                file_path=file_path,
                line_number=line_no,
                column_number=getattr(node, "col_offset", 1),
                vulnerable_code=code_line,
                recommended_fix="json.loads(data)",
                cvss_score=9.8
            ))

        # 5. yaml.load without SafeLoader
        elif func_name == "yaml.load":
            has_safe = False
            for kw in node.keywords:
                if kw.arg == "Loader" and "SafeLoader" in ast.unparse(kw.value):
                    has_safe = True
            if not has_safe:
                issues.append(CodeVulnerabilityIssue(
                    rule_id="DES-002",
                    category=IssueCategory.INSECURE_DESERIALIZATION,
                    severity=IssueSeverity.HIGH,
                    cwe_id="CWE-502",
                    title="Insecure YAML Deserialization without SafeLoader",
                    description="yaml.load without SafeLoader can instantiate dangerous custom classes.",
                    file_path=file_path,
                    line_number=line_no,
                    column_number=getattr(node, "col_offset", 1),
                    vulnerable_code=code_line,
                    recommended_fix="yaml.safe_load(data)",
                    cvss_score=8.5
                ))

        # 6. Weak Hashing: hashlib.md5 / hashlib.sha1
        elif func_name in ("hashlib.md5", "hashlib.sha1"):
            issues.append(CodeVulnerabilityIssue(
                rule_id="CRY-001",
                category=IssueCategory.CRYPTO,
                severity=IssueSeverity.MEDIUM,
                cwe_id="CWE-327",
                title=f"Insecure Hash Function: {func_name}()",
                description=f"{func_name}() is cryptographically broken and vulnerable to collision attacks.",
                file_path=file_path,
                line_number=line_no,
                column_number=getattr(node, "col_offset", 1),
                vulnerable_code=code_line,
                recommended_fix="hashlib.sha256()",
                cvss_score=5.5
            ))

    def _get_call_name(self, node: ast.AST) -> str:
        """Resolves function call attribute chain (e.g., 'os.system', 'hashlib.sha1')."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val = self._get_call_name(node.value)
            return f"{val}.{node.attr}" if val else node.attr
        return ""
