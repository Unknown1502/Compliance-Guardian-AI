# User Guide - Compliance Guardian AI

## Table of Contents

1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Running Scans](#running-scans)
4. [Understanding Results](#understanding-results)
5. [Working with Frameworks](#working-with-frameworks)
6. [Remediation Guide](#remediation-guide)
7. [Advanced Features](#advanced-features)
8. [Troubleshooting](#troubleshooting)
9. [Best Practices](#best-practices)

---

## Introduction

Compliance Guardian AI is an automated compliance monitoring system that helps you:
- 🔍 **Scan code** for regulatory compliance violations
- 🛡️ **Detect risks** across GDPR, HIPAA, and PCI-DSS frameworks
- 🤖 **Get AI-powered** remediation suggestions
- 📊 **Generate reports** for audit and compliance tracking

### Who Should Use This Tool?

- **Developers**: Catch compliance issues before deployment
- **Security Teams**: Audit codebases for violations
- **Compliance Officers**: Generate compliance reports
- **DevOps Engineers**: Integrate into CI/CD pipelines

---

## Getting Started

### Prerequisites

- Python 3.11 or higher
- Internet connection (for API calls)
- Basic understanding of compliance frameworks (optional)

### Installation

1. **Clone the repository**:
```bash
git clone https://github.com/your-org/compliance-guardian-ai.git
cd compliance-guardian-ai
```

2. **Create virtual environment**:
```bash
python -m venv venv
```

3. **Activate virtual environment**:

**Windows**:
```cmd
venv\Scripts\activate
```

**Linux/Mac**:
```bash
source venv/bin/activate
```

4. **Install dependencies**:
```bash
pip install -r requirements.txt
```

5. **Verify installation**:
```bash
python demo.py
```

---

## Running Scans

### Method 1: Interactive Demo

The easiest way to get started is with the interactive demo:

```bash
python demo.py
```

**Demo Features**:
- ✅ Pre-configured sample code
- ✅ All frameworks included
- ✅ Step-by-step explanations
- ✅ Automatic report generation

**Demo Flow**:
1. Welcome screen with project information
2. Sample code display (payment processing violation)
3. Scan execution with progress indicators
4. Results display with color-coded violations
5. Remediation suggestions
6. Report saved to `reports/` folder

### Method 2: Automated Demo

For quick testing without interaction:

```bash
python demo_auto.py
```

Automatically runs all scan types and generates reports.

### Method 3: Animated Demo (Video Recording)

For presentations and demos:

```bash
python demo_animated.py
```

**Features**:
- 3-minute animated sequence
- Character-by-character typing effect
- Professional color coding
- Suitable for screen recording

### Method 4: Python API

For programmatic access:

```python
import requests

url = "https://gluwdyp4ii.execute-api.us-east-1.amazonaws.com/production/scan"

payload = {
    "code": """
    def process_payment(card_number, cvv):
        payment = {'card': card_number, 'cvv': cvv}
        db.save(payment)
    """,
    "scan_type": "comprehensive",
    "frameworks": ["GDPR", "HIPAA", "PCI-DSS"]
}

response = requests.post(url, json=payload)
result = response.json()

print(f"Compliance Score: {result['analysis']['compliance_score']}")
print(f"Violations Found: {len(result['analysis']['violations'])}")
```

### Method 5: Command Line

Using examples from the `examples/` directory:

```bash
# Basic scan
python examples/basic_scan.py

# Generate reports
python examples/generate_reports.py

# API usage examples
python examples/api_usage.py

# Automated remediation
python examples/automated_remediation.py
```

---

## Understanding Results

### Scan Response Structure

```json
{
  "scan_id": "scan-20251017-123456",
  "timestamp": "2025-10-17T12:34:56Z",
  "status": "completed",
  "scan_type": "comprehensive",
  "frameworks": ["GDPR", "HIPAA", "PCI-DSS"],
  "analysis": {
    "summary": "AI-generated analysis",
    "violations": [...],
    "compliance_score": 65,
    "risk_level": "high"
  },
  "recommendations": [...],
  "execution_time": 7.5
}
```

### Compliance Scores

| Score Range | Rating | Meaning |
|-------------|--------|---------|
| 90-100 | Excellent | Minimal violations, well-protected |
| 70-89 | Good | Some issues, mostly compliant |
| 50-69 | Fair | Multiple violations, needs attention |
| 30-49 | Poor | Significant compliance gaps |
| 0-29 | Critical | Severe violations, immediate action needed |

### Severity Levels

**🔴 Critical**
- Immediate risk of data breach
- Direct regulatory violation
- Potential for significant fines
- **Example**: CVV storage, unencrypted PII

**🟠 High**
- Significant compliance gap
- Potential for exploitation
- Could lead to audit failure
- **Example**: Missing encryption, weak access controls

**🟡 Medium**
- Moderate compliance issue
- Should be addressed soon
- May escalate if ignored
- **Example**: Incomplete logging, missing MFA

**🟢 Low**
- Minor compliance gap
- Low immediate risk
- Best practice recommendation
- **Example**: Documentation gaps, outdated libraries

### Violation Types

#### GDPR Violations

| Type | Description | Example |
|------|-------------|---------|
| `pii_unencrypted` | PII stored without encryption | `user_email = "test@example.com"` |
| `missing_consent` | No user consent mechanism | Processing data without opt-in |
| `data_retention` | Excessive data retention | Storing data indefinitely |
| `no_erasure` | No data deletion capability | Missing delete user function |

#### HIPAA Violations

| Type | Description | Example |
|------|-------------|---------|
| `phi_unencrypted` | PHI not encrypted | `patient_ssn = "123-45-6789"` |
| `no_access_controls` | Missing access restrictions | Public database access |
| `no_audit_logs` | Missing activity logging | No record of data access |
| `no_mfa` | No multi-factor authentication | Password-only authentication |

#### PCI-DSS Violations

| Type | Description | Example |
|------|-------------|---------|
| `card_data_unencrypted` | Card data not encrypted | Storing card numbers in plain text |
| `cvv_stored` | CVV/CVC stored (prohibited) | `cvv = "123"` in database |
| `no_network_security` | Weak network controls | Open ports, no firewall |
| `no_vulnerability_scan` | Missing security scans | No regular penetration testing |

---

## Working with Frameworks

### GDPR (General Data Protection Regulation)

**Scope**: European Union data privacy

**Key Principles**:
- **Lawfulness**: Legal basis for processing
- **Purpose Limitation**: Collect only what's needed
- **Data Minimization**: Store minimal data
- **Accuracy**: Keep data up-to-date
- **Storage Limitation**: Delete when no longer needed
- **Integrity**: Ensure data security

**What the Scanner Checks**:
- ✅ PII encryption (email, name, address, phone)
- ✅ Consent mechanisms
- ✅ Data retention policies
- ✅ Right to erasure implementation
- ✅ Data portability capabilities
- ✅ Breach notification procedures

**Example Scan**:
```python
payload = {
    "code": code_sample,
    "scan_type": "gdpr",
    "frameworks": ["GDPR"]
}
```

### HIPAA (Health Insurance Portability and Accountability Act)

**Scope**: US healthcare data protection

**Protected Health Information (PHI)**:
- Medical records
- Social Security numbers
- Health insurance details
- Patient identifiers

**What the Scanner Checks**:
- ✅ PHI encryption at rest and in transit
- ✅ Access controls and authentication
- ✅ Audit logging of PHI access
- ✅ Multi-factor authentication
- ✅ Data backup procedures
- ✅ Breach notification compliance

**Example Scan**:
```python
payload = {
    "code": healthcare_code,
    "scan_type": "hipaa",
    "frameworks": ["HIPAA"]
}
```

### PCI-DSS (Payment Card Industry Data Security Standard)

**Scope**: Payment card data security

**Cardholder Data**:
- Card number (PAN)
- Cardholder name
- Expiration date
- **NEVER**: CVV/CVC (prohibited from storage)

**What the Scanner Checks**:
- ✅ Card data encryption
- ✅ CVV storage prohibition compliance
- ✅ Network security controls
- ✅ Access control mechanisms
- ✅ Vulnerability management
- ✅ Security monitoring and testing

**Example Scan**:
```python
payload = {
    "code": payment_code,
    "scan_type": "pci-dss",
    "frameworks": ["PCI-DSS"]
}
```

### Comprehensive Scan

Scans against **all frameworks** simultaneously:

```python
payload = {
    "code": code_sample,
    "scan_type": "comprehensive",
    "frameworks": ["GDPR", "HIPAA", "PCI-DSS"]
}
```

**When to Use**:
- Mixed-domain applications (e.g., healthcare payment systems)
- Complete compliance audit
- Pre-deployment security check
- Regulatory audit preparation

---

## Remediation Guide

### Step 1: Prioritize Violations

1. **Critical violations first**: Address immediately
2. **High severity next**: Within 1-2 weeks
3. **Medium severity**: Within 1 month
4. **Low severity**: Include in next sprint

### Step 2: Understand the Violation

Each violation includes:
- **Description**: What the issue is
- **Line number**: Where it occurs (if applicable)
- **Framework**: Which regulation it violates
- **Recommendation**: How to fix it

**Example Violation**:
```json
{
  "severity": "critical",
  "framework": "PCI-DSS",
  "type": "cvv_stored",
  "description": "CVV codes are stored in violation of PCI-DSS Requirement 3.2",
  "line": 3,
  "recommendation": "Remove CVV storage completely. Use tokenization for recurring payments."
}
```

### Step 3: Apply Remediation

#### Example 1: CVV Storage (PCI-DSS)

**Before** (❌ Violates PCI-DSS):
```python
def process_payment(card_number, cvv, exp_date):
    payment = {
        'card': card_number,
        'cvv': cvv,  # ❌ NEVER store CVV
        'exp': exp_date
    }
    db.save(payment)
```

**After** (✅ Compliant):
```python
def process_payment(card_number, exp_date):
    # Use tokenization service (e.g., Stripe, Square)
    token = payment_gateway.tokenize(card_number, exp_date)
    
    payment = {
        'token': token,  # ✅ Store token, not card data
        'exp': exp_date
    }
    db.save(payment)
```

#### Example 2: Unencrypted PII (GDPR)

**Before** (❌ Violates GDPR):
```python
def store_user(email, name):
    user = {
        'email': email,  # ❌ Plain text PII
        'name': name
    }
    db.save(user)
```

**After** (✅ Compliant):
```python
from cryptography.fernet import Fernet

def store_user(email, name):
    cipher = Fernet(encryption_key)
    
    user = {
        'email': cipher.encrypt(email.encode()),  # ✅ Encrypted
        'name': cipher.encrypt(name.encode())
    }
    db.save(user)
```

#### Example 3: Missing Access Controls (HIPAA)

**Before** (❌ Violates HIPAA):
```python
@app.route('/patient/<patient_id>')
def get_patient(patient_id):
    return db.query(f"SELECT * FROM patients WHERE id={patient_id}")
```

**After** (✅ Compliant):
```python
@app.route('/patient/<patient_id>')
@require_auth  # ✅ Authentication required
@require_role('healthcare_provider')  # ✅ Authorization check
@audit_log  # ✅ Audit logging
def get_patient(patient_id):
    # Use parameterized queries (prevents SQL injection)
    return db.query_secure("SELECT * FROM patients WHERE id=?", patient_id)
```

### Step 4: Re-scan

After applying fixes:

```bash
python demo.py
```

Or programmatically:
```python
response = requests.post(url, json=payload)
new_score = response.json()['analysis']['compliance_score']
print(f"New compliance score: {new_score}")
```

### Step 5: Document Changes

Create a remediation log:

```markdown
## Remediation Log

### 2025-10-17: CVV Storage Violation

- **Violation ID**: VIO-PCI-001
- **Severity**: Critical
- **Framework**: PCI-DSS
- **Action Taken**: Removed CVV storage, implemented tokenization
- **Verification**: Re-scan shows 0 CVV violations
- **Compliance Score**: 45 → 85
```

---

## Advanced Features

### 1. Custom Scan Options

```python
payload = {
    "code": code_sample,
    "scan_type": "comprehensive",
    "options": {
        "include_remediation": True,  # Get AI remediation
        "severity_filter": "critical",  # Only critical violations
        "max_violations": 10,  # Limit results
        "detailed_analysis": True  # Verbose output
    }
}
```

### 2. Batch Scanning

Scan multiple files:

```python
files = ['app.py', 'models.py', 'views.py']

for file in files:
    with open(file, 'r') as f:
        code = f.read()
    
    response = requests.post(url, json={
        "code": code,
        "scan_type": "comprehensive",
        "target": file
    })
    
    print(f"{file}: {response.json()['analysis']['compliance_score']}")
```

### 3. CI/CD Integration

**GitHub Actions Example**:

```yaml
name: Compliance Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Scan for violations
        run: |
          python examples/basic_scan.py
          
      - name: Check compliance score
        run: |
          SCORE=$(python get_score.py)
          if [ $SCORE -lt 70 ]; then
            echo "Compliance score too low: $SCORE"
            exit 1
          fi
```

### 4. Custom Policies

Create custom compliance rules (advanced):

```python
custom_policy = {
    "name": "Company Security Policy",
    "rules": [
        {
            "id": "CSP-001",
            "pattern": "password.*=.*['\"].*['\"]",
            "severity": "critical",
            "message": "Hardcoded password detected"
        }
    ]
}
```

---

## Troubleshooting

### Issue: "Connection Error"

**Cause**: Network connectivity or API unavailable

**Solution**:
```bash
# Test connectivity
ping execute-api.us-east-1.amazonaws.com

# Check API status
curl https://gluwdyp4ii.execute-api.us-east-1.amazonaws.com/production/scan
```

### Issue: "Timeout Error"

**Cause**: Large code sample or slow API response

**Solution**:
```python
# Increase timeout
response = requests.post(url, json=payload, timeout=60)
```

### Issue: "Invalid JSON"

**Cause**: Malformed request

**Solution**:
```python
import json

# Validate JSON before sending
try:
    json.dumps(payload)
except ValueError as e:
    print(f"Invalid JSON: {e}")
```

### Issue: "Low Compliance Score"

**Cause**: Multiple violations detected

**Solution**:
1. Review violation list
2. Sort by severity
3. Apply remediations
4. Re-scan

### Issue: "No Violations Found" (but code has issues)

**Cause**: AI limitations or edge case

**Solution**:
- Try different scan_type
- Break code into smaller chunks
- Add more context to code sample

---

## Best Practices

### 1. Regular Scanning

```bash
# Daily automated scan
0 9 * * * cd /path/to/project && python demo_auto.py
```

### 2. Pre-Commit Hooks

```bash
#!/bin/sh
# .git/hooks/pre-commit

python examples/basic_scan.py
if [ $? -ne 0 ]; then
    echo "Compliance scan failed. Commit aborted."
    exit 1
fi
```

### 3. Incremental Fixes

Don't try to fix everything at once:
- Week 1: Critical violations
- Week 2: High violations
- Week 3: Medium violations
- Week 4: Low violations + documentation

### 4. Documentation

Keep a compliance journal:
```markdown
# Compliance Journal

## 2025-10-17
- Ran comprehensive scan
- Found 5 critical violations
- Applied PCI-DSS tokenization fix
- Score improved: 45 → 75

## 2025-10-18
- Re-scanned after fixes
- 0 critical violations
- 2 high violations remaining
- Next: Implement audit logging
```

### 5. Team Training

- Share scan results in team meetings
- Create internal compliance guides
- Run monthly compliance reviews

---

## Next Steps

1. ✅ **Complete the demo**: Run `python demo.py`
2. 📖 **Read API docs**: See `docs/API_DOCUMENTATION.md`
3. 🏗️ **Understand architecture**: See `docs/ARCHITECTURE.md`
4. 🚀 **Deploy your own**: See `DEPLOYMENT_SUMMARY.md`
5. 🤝 **Contribute**: Submit issues and PRs

---

## Support

- **Documentation**: Full docs in `docs/` folder
- **Issues**: GitHub Issues
- **Examples**: Check `examples/` directory
- **Community**: Join our Slack channel

---

## Appendix

### A. Compliance Frameworks Quick Reference

| Framework | Focus | Key Requirements |
|-----------|-------|------------------|
| GDPR | Data Privacy | Encryption, consent, erasure |
| HIPAA | Healthcare | PHI protection, access controls |
| PCI-DSS | Payment Security | No CVV storage, card encryption |

### B. Useful Commands

```bash
# Run demo
python demo.py

# Automated demo
python demo_auto.py

# Animated demo (for recording)
python demo_animated.py

# Run tests
pytest tests/ -v

# Check coverage
pytest --cov=src tests/

# Generate HTML reports
python examples/generate_reports.py
```

### C. Additional Resources

- [GDPR Official Text](https://gdpr.eu/)
- [HIPAA Guide](https://www.hhs.gov/hipaa)
- [PCI-DSS Standards](https://www.pcisecuritystandards.org/)
- [AWS Bedrock Documentation](https://docs.aws.amazon.com/bedrock/)

---

**Happy Scanning! 🚀**
