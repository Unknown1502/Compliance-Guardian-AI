# API Documentation - Compliance Guardian AI

## Overview

The Compliance Guardian AI provides a RESTful API for automated compliance scanning, violation detection, and remediation across multiple regulatory frameworks.

**Base URL**: `https://gluwdyp4ii.execute-api.us-east-1.amazonaws.com/production`

---

## Authentication

Currently, the API is open for hackathon demonstration. In production, authentication would be handled via:
- AWS IAM roles
- API keys
- OAuth 2.0 tokens

---

## Endpoints

### POST /scan

Initiates a compliance scan on provided code or infrastructure configuration.

**Endpoint**: `/scan` 
**Method**: `POST` 
**Content-Type**: `application/json`

#### Request Body

```json
{
 "code": "string (required) - Source code or configuration to scan",
 "scan_type": "string (optional) - Scan type: 'gdpr', 'hipaa', 'pci-dss', or 'comprehensive'",
 "frameworks": ["array (optional) - List of frameworks: ['GDPR', 'HIPAA', 'PCI-DSS']"],
 "target": "string (optional) - Target identifier",
 "options": {
 "include_remediation": "boolean (optional) - Include remediation suggestions",
 "severity_filter": "string (optional) - Filter by severity: 'critical', 'high', 'medium', 'low'"
 }
}
```

#### Request Example

```json
{
 "code": "def process_payment(card_number, cvv):\n payment = {'card': card_number, 'cvv': cvv}\n db.save(payment)",
 "scan_type": "comprehensive",
 "frameworks": ["GDPR", "HIPAA", "PCI-DSS"],
 "options": {
 "include_remediation": true
 }
}
```

#### Response Format

**Success Response** (200 OK):

```json
{
 "statusCode": 200,
 "body": {
 "scan_id": "scan-20251017-123456",
 "timestamp": "2025-10-17T12:34:56Z",
 "status": "completed",
 "scan_type": "comprehensive",
 "frameworks": ["GDPR", "HIPAA", "PCI-DSS"],
 "analysis": {
 "summary": "AI-generated compliance analysis",
 "violations": [
 {
 "id": "VIO-PCI-001",
 "framework": "PCI-DSS",
 "severity": "critical",
 "type": "card_data_unencrypted",
 "description": "CVV codes stored in violation of PCI-DSS 3.2",
 "line": 2,
 "recommendation": "Remove CVV storage and implement tokenization"
 }
 ],
 "compliance_score": 65,
 "risk_level": "high"
 },
 "recommendations": [
 "Implement data encryption at rest",
 "Enable access controls and MFA",
 "Add audit logging"
 ],
 "execution_time": 7.5
 }
}
```

**Error Response** (400 Bad Request):

```json
{
 "statusCode": 400,
 "body": {
 "error": "Invalid request",
 "message": "Missing required field: code"
 }
}
```

**Error Response** (500 Internal Server Error):

```json
{
 "statusCode": 500,
 "body": {
 "error": "Internal server error",
 "message": "Failed to process scan request"
 }
}
```

---

## Response Fields

### Scan Response

| Field | Type | Description |
|-------|------|-------------|
| `scan_id` | string | Unique identifier for the scan |
| `timestamp` | string | ISO 8601 timestamp of scan completion |
| `status` | string | Scan status: 'completed', 'failed', 'partial' |
| `scan_type` | string | Type of scan performed |
| `frameworks` | array | List of frameworks scanned against |
| `analysis` | object | Detailed analysis results |
| `recommendations` | array | AI-generated recommendations |
| `execution_time` | number | Time taken in seconds |

### Violation Object

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique violation identifier |
| `framework` | string | Compliance framework (GDPR, HIPAA, PCI-DSS) |
| `severity` | string | Severity level: 'critical', 'high', 'medium', 'low' |
| `type` | string | Violation type identifier |
| `description` | string | Human-readable description |
| `line` | number | Line number in code (if applicable) |
| `recommendation` | string | Remediation suggestion |

---

## Code Examples

### Python

```python
import requests
import json

# API endpoint
url = "https://gluwdyp4ii.execute-api.us-east-1.amazonaws.com/production/scan"

# Sample code to scan
code = """
def process_payment(card_number, cvv, email):
 # Storing sensitive data - compliance violation
 payment = {
 'card': card_number,
 'cvv': cvv,
 'email': email
 }
 db.save(payment)
"""

# Request payload
payload = {
 "code": code,
 "scan_type": "comprehensive",
 "frameworks": ["GDPR", "HIPAA", "PCI-DSS"],
 "options": {
 "include_remediation": True
 }
}

# Make request
response = requests.post(url, json=payload)

# Parse response
if response.status_code == 200:
 result = response.json()
 print(f"Scan ID: {result['scan_id']}")
 print(f"Violations: {len(result['analysis']['violations'])}")
 print(f"Compliance Score: {result['analysis']['compliance_score']}")
else:
 print(f"Error: {response.status_code}")
 print(response.text)
```

### cURL

```bash
curl -X POST https://gluwdyp4ii.execute-api.us-east-1.amazonaws.com/production/scan \
 -H "Content-Type: application/json" \
 -d '{
 "code": "def get_user(id): return db.query(f\"SELECT * FROM users WHERE id={id}\")",
 "scan_type": "gdpr",
 "options": {
 "include_remediation": true
 }
 }'
```

### JavaScript (Node.js)

```javascript
const axios = require('axios');

const url = 'https://gluwdyp4ii.execute-api.us-east-1.amazonaws.com/production/scan';

const payload = {
 code: `
 def store_patient_data(patient_id, medical_record):
 # No encryption - HIPAA violation
 db.save(patient_id, medical_record)
 `,
 scan_type: 'hipaa',
 options: {
 include_remediation: true
 }
};

axios.post(url, payload)
 .then(response => {
 console.log('Scan ID:', response.data.scan_id);
 console.log('Violations:', response.data.analysis.violations.length);
 console.log('Compliance Score:', response.data.analysis.compliance_score);
 })
 .catch(error => {
 console.error('Error:', error.response?.status, error.message);
 });
```

---

## Scan Types

### Comprehensive Scan
Scans against all supported compliance frameworks.

```json
{
 "scan_type": "comprehensive",
 "frameworks": ["GDPR", "HIPAA", "PCI-DSS"]
}
```

### GDPR Scan
Focuses on data privacy, consent, and data protection.

```json
{
 "scan_type": "gdpr"
}
```

**Checks for**:
- Unencrypted PII (Personally Identifiable Information)
- Missing consent mechanisms
- Data retention violations
- Right to erasure compliance
- Data portability requirements

### HIPAA Scan
Focuses on healthcare data protection.

```json
{
 "scan_type": "hipaa"
}
```

**Checks for**:
- Unencrypted PHI (Protected Health Information)
- Missing access controls
- Audit logging gaps
- MFA enforcement
- Data breach notification readiness

### PCI-DSS Scan
Focuses on payment card data security.

```json
{
 "scan_type": "pci-dss"
}
```

**Checks for**:
- Unencrypted card data
- CVV storage violations
- Network security gaps
- Access control weaknesses
- Vulnerability management issues

---

## Rate Limits

Currently no rate limits for hackathon demonstration.

**Production Recommendations**:
- 100 requests per minute per API key
- 10,000 requests per day per organization

---

## Error Codes

| Code | Meaning | Resolution |
|------|---------|------------|
| 400 | Bad Request | Check request format and required fields |
| 401 | Unauthorized | Verify API credentials |
| 403 | Forbidden | Check API key permissions |
| 429 | Too Many Requests | Implement rate limiting or retry with backoff |
| 500 | Internal Server Error | Contact support or retry later |
| 503 | Service Unavailable | AWS service temporarily unavailable |

---

## Best Practices

### 1. Error Handling

Always implement proper error handling:

```python
try:
 response = requests.post(url, json=payload, timeout=30)
 response.raise_for_status()
 result = response.json()
except requests.exceptions.Timeout:
 print("Request timed out")
except requests.exceptions.HTTPError as e:
 print(f"HTTP error: {e}")
except Exception as e:
 print(f"Error: {e}")
```

### 2. Pagination

For large codebases, split into multiple requests:

```python
def scan_files(files, batch_size=10):
 for i in range(0, len(files), batch_size):
 batch = files[i:i+batch_size]
 # Process batch
```

### 3. Caching

Cache scan results for unchanged code:

```python
import hashlib

def get_code_hash(code):
 return hashlib.sha256(code.encode()).hexdigest()

# Check cache before scanning
code_hash = get_code_hash(code)
if code_hash in cache:
 return cache[code_hash]
```

### 4. Asynchronous Requests

For multiple scans, use async requests:

```python
import asyncio
import aiohttp

async def scan_async(session, code):
 async with session.post(url, json={"code": code}) as response:
 return await response.json()

async def scan_multiple(codes):
 async with aiohttp.ClientSession() as session:
 tasks = [scan_async(session, code) for code in codes]
 return await asyncio.gather(*tasks)
```

---

## Webhooks

**Coming Soon**: Webhook support for long-running scans.

```json
{
 "code": "...",
 "scan_type": "comprehensive",
 "webhook_url": "https://your-app.com/webhook",
 "webhook_secret": "your-secret-key"
}
```

---

## SDK Support

**Planned SDKs**:
- Python SDK (beta)
- JavaScript/TypeScript SDK
- Java SDK
- Go SDK

---

## Support

- **Documentation**: https://github.com/your-repo/docs
- **Issues**: https://github.com/your-repo/issues
- **Email**: support@compliance-guardian.ai
- **Slack**: compliance-guardian.slack.com

---

## Changelog

### v1.0.0 (2025-10-17)
- Initial API release
- Support for GDPR, HIPAA, PCI-DSS
- AWS Bedrock integration (Nova Pro + Claude 3.5 Sonnet)
- Real-time compliance scanning
- AI-powered remediation suggestions

---

## License

See LICENSE file for details.
