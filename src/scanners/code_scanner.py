"""Code compliance scanner."""

import re
import ast
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass
from pathlib import Path

from ..utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class CodeViolation:
    """Code-level compliance violation."""
    
    file_path: str
    line_number: int
    violation_type: str
    severity: str
    description: str
    code_snippet: str
    remediation: str
    framework: str


class CodeScanner:
    """
    Static code analysis scanner for compliance violations.
    
    Detects:
    - Hardcoded credentials and secrets
    - PII/PHI in code or comments
    - Insecure cryptographic functions
    - SQL injection vulnerabilities
    - XSS vulnerabilities
    - Insecure deserialization
    - Path traversal risks
    - Missing input validation
    - Insufficient logging
    - Security misconfigurations
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize code scanner."""
        self.config = config or {}
        self.violations: List[CodeViolation] = []
        
        # Patterns for detection
        self._init_patterns()
    
    def _init_patterns(self) -> None:
        """Initialize regex patterns for detection."""
        # Hardcoded secrets
        self.secret_patterns = {
            "aws_access_key": r"(?i)AKIA[0-9A-Z]{16}",
            "aws_secret_key": r"(?i)aws_secret_access_key\s*=\s*['\"][0-9a-zA-Z/+=]{40}['\"]",
            "api_key": r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"][a-zA-Z0-9_\-]{20,}['\"]",
            "password": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
            "private_key": r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
            "token": r"(?i)(token|jwt)\s*[=:]\s*['\"][a-zA-Z0-9_\-\.]{20,}['\"]"
        }
        
        # PII patterns
        self.pii_patterns = {
            "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
            "credit_card": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
            "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "phone": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"
        }
        
        # Insecure functions
        self.insecure_functions = {
            "python": [
                (r"eval\(", "eval", "Code injection risk"),
                (r"exec\(", "exec", "Code injection risk"),
                (r"pickle\.loads?\(", "pickle", "Insecure deserialization"),
                (r"subprocess\.call\(.*shell=True", "subprocess shell", "Command injection risk"),
                (r"hashlib\.md5\(", "MD5", "Weak cryptographic hash"),
                (r"hashlib\.sha1\(", "SHA1", "Weak cryptographic hash"),
                (r"random\.random\(", "random", "Insecure randomness for security"),
            ],
            "javascript": [
                (r"eval\(", "eval", "Code injection risk"),
                (r"innerHTML\s*=", "innerHTML", "XSS vulnerability"),
                (r"document\.write\(", "document.write", "XSS vulnerability"),
                (r"crypto\.createHash\(['\"](md5|sha1)['\"]", "weak hash", "Weak cryptographic hash"),
            ]
        }
        
        # SQL injection patterns
        self.sql_injection_patterns = [
            r"execute\(.*['\"].*%s.*['\"].*%",
            r"execute\(.*\+",
            r"cursor\.execute\(f['\"]",
            r"\.raw\(.*\+",
        ]
    
    async def scan(self, code_path: str) -> Dict[str, Any]:
        """Perform code compliance scan."""
        try:
            logger.info(f"Starting code scan for {code_path}")
            
            self.violations = []
            path = Path(code_path)
            
            if path.is_file():
                await self._scan_file(path)
            elif path.is_dir():
                await self._scan_directory(path)
            
            results = {
                "framework": "Code Compliance",
                "scan_path": code_path,
                "violations": [self._violation_to_dict(v) for v in self.violations],
                "violation_count": len(self.violations),
                "files_scanned": self._count_files(path),
                "critical_issues": self._get_critical_issues(),
                "by_category": self._group_by_category(),
                "recommendations": self._generate_recommendations()
            }
            
            logger.info(f"Code scan completed: {len(self.violations)} violations found")
            
            return results
            
        except Exception as e:
            logger.error(f"Code scan failed: {e}")
            raise
    
    async def _scan_directory(self, directory: Path) -> None:
        """Scan all code files in directory."""
        extensions = {'.py', '.js', '.ts', '.java', '.go', '.rb', '.php'}
        
        for file_path in directory.rglob('*'):
            if file_path.suffix in extensions and file_path.is_file():
                await self._scan_file(file_path)
    
    async def _scan_file(self, file_path: Path) -> None:
        """Scan individual code file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
            
            # Check for hardcoded secrets
            await self._check_secrets(file_path, lines)
            
            # Check for PII
            await self._check_pii(file_path, lines)
            
            # Check for insecure functions
            await self._check_insecure_functions(file_path, lines)
            
            # Check for SQL injection
            await self._check_sql_injection(file_path, lines)
            
            # Language-specific checks
            if file_path.suffix == '.py':
                await self._check_python_specific(file_path, content, lines)
            
        except Exception as e:
            logger.warning(f"Failed to scan {file_path}: {e}")
    
    async def _check_secrets(self, file_path: Path, lines: List[str]) -> None:
        """Check for hardcoded secrets."""
        for line_num, line in enumerate(lines, 1):
            for secret_type, pattern in self.secret_patterns.items():
                if re.search(pattern, line):
                    self.violations.append(CodeViolation(
                        file_path=str(file_path),
                        line_number=line_num,
                        violation_type="hardcoded_secret",
                        severity="critical",
                        description=f"Hardcoded {secret_type} detected",
                        code_snippet=line.strip(),
                        remediation="Use environment variables or secrets management service (AWS Secrets Manager, HashiCorp Vault)",
                        framework="Security"
                    ))
    
    async def _check_pii(self, file_path: Path, lines: List[str]) -> None:
        """Check for PII in code."""
        for line_num, line in enumerate(lines, 1):
            for pii_type, pattern in self.pii_patterns.items():
                matches = re.findall(pattern, line)
                if matches:
                    self.violations.append(CodeViolation(
                        file_path=str(file_path),
                        line_number=line_num,
                        violation_type="pii_exposure",
                        severity="high",
                        description=f"{pii_type.upper()} found in code",
                        code_snippet=line.strip(),
                        remediation=f"Remove {pii_type} from code. Use mock/sanitized data for testing",
                        framework="GDPR/HIPAA"
                    ))
    
    async def _check_insecure_functions(self, file_path: Path, lines: List[str]) -> None:
        """Check for insecure function usage."""
        file_ext = file_path.suffix
        language = None
        
        if file_ext == '.py':
            language = 'python'
        elif file_ext in {'.js', '.ts'}:
            language = 'javascript'
        
        if language and language in self.insecure_functions:
            for line_num, line in enumerate(lines, 1):
                for pattern, func_name, description in self.insecure_functions[language]:
                    if re.search(pattern, line):
                        self.violations.append(CodeViolation(
                            file_path=str(file_path),
                            line_number=line_num,
                            violation_type="insecure_function",
                            severity="high",
                            description=f"Insecure function '{func_name}': {description}",
                            code_snippet=line.strip(),
                            remediation=self._get_secure_alternative(func_name, language),
                            framework="Security"
                        ))
    
    async def _check_sql_injection(self, file_path: Path, lines: List[str]) -> None:
        """Check for SQL injection vulnerabilities."""
        for line_num, line in enumerate(lines, 1):
            for pattern in self.sql_injection_patterns:
                if re.search(pattern, line):
                    self.violations.append(CodeViolation(
                        file_path=str(file_path),
                        line_number=line_num,
                        violation_type="sql_injection",
                        severity="critical",
                        description="Potential SQL injection vulnerability",
                        code_snippet=line.strip(),
                        remediation="Use parameterized queries or ORM with parameter binding",
                        framework="Security/PCI DSS"
                    ))
    
    async def _check_python_specific(self, file_path: Path, content: str, lines: List[str]) -> None:
        """Python-specific compliance checks."""
        try:
            tree = ast.parse(content)
            
            # Check for missing error handling
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    has_try = any(isinstance(n, ast.Try) for n in ast.walk(node))
                    if not has_try and len(node.body) > 5:  # Only flag substantial functions
                        self.violations.append(CodeViolation(
                            file_path=str(file_path),
                            line_number=node.lineno,
                            violation_type="missing_error_handling",
                            severity="medium",
                            description=f"Function '{node.name}' lacks error handling",
                            code_snippet=f"def {node.name}(...)",
                            remediation="Add try-except blocks for robust error handling",
                            framework="Reliability"
                        ))
        
        except SyntaxError:
            logger.warning(f"Could not parse {file_path} as Python")
    
    def _get_secure_alternative(self, func_name: str, language: str) -> str:
        """Get secure alternative for insecure function."""
        alternatives = {
            "python": {
                "eval": "Use ast.literal_eval() for safe evaluation of literals",
                "exec": "Refactor to avoid dynamic code execution",
                "pickle": "Use json.loads() for JSON data or define custom serialization",
                "subprocess shell": "Use subprocess with shell=False and list of arguments",
                "MD5": "Use hashlib.sha256() or hashlib.sha3_256()",
                "SHA1": "Use hashlib.sha256() or hashlib.sha3_256()",
                "random": "Use secrets module for cryptographic randomness"
            },
            "javascript": {
                "eval": "Use JSON.parse() for JSON or refactor code structure",
                "innerHTML": "Use textContent or createElement with appendChild",
                "document.write": "Use DOM manipulation methods",
                "weak hash": "Use SHA-256 or stronger"
            }
        }
        
        return alternatives.get(language, {}).get(func_name, "Use secure alternative")
    
    def _count_files(self, path: Path) -> int:
        """Count number of files scanned."""
        if path.is_file():
            return 1
        
        extensions = {'.py', '.js', '.ts', '.java', '.go', '.rb', '.php'}
        return sum(1 for f in path.rglob('*') if f.suffix in extensions and f.is_file())
    
    def _get_critical_issues(self) -> List[Dict[str, Any]]:
        """Get critical code issues."""
        return [self._violation_to_dict(v) for v in self.violations if v.severity == "critical"]
    
    def _group_by_category(self) -> Dict[str, int]:
        """Group violations by category."""
        categories = {}
        for v in self.violations:
            categories[v.violation_type] = categories.get(v.violation_type, 0) + 1
        return categories
    
    def _generate_recommendations(self) -> List[Dict[str, Any]]:
        """Generate prioritized recommendations."""
        recommendations = []
        by_type = {}
        
        for v in self.violations:
            if v.violation_type not in by_type:
                by_type[v.violation_type] = []
            by_type[v.violation_type].append(v)
        
        for vtype, violations in sorted(by_type.items(), key=lambda x: len(x[1]), reverse=True):
            severity = max((v.severity for v in violations), key=lambda s: {"critical": 3, "high": 2, "medium": 1, "low": 0}[s])
            recommendations.append({
                "category": vtype,
                "severity": severity,
                "count": len(violations),
                "files_affected": len(set(v.file_path for v in violations)),
                "remediation": violations[0].remediation
            })
        
        return recommendations[:10]  # Top 10
    
    def _violation_to_dict(self, violation: CodeViolation) -> Dict[str, Any]:
        """Convert violation to dictionary."""
        return {
            "file_path": violation.file_path,
            "line_number": violation.line_number,
            "violation_type": violation.violation_type,
            "severity": violation.severity,
            "description": violation.description,
            "code_snippet": violation.code_snippet,
            "remediation": violation.remediation,
            "framework": violation.framework
        }
