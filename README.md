# Compliance Guardian AI

> **Autonomous Compliance & Privacy Guardian Multi-Agent System** 
> Powered by AWS Bedrock, Amazon Q, and Amazon Nova

[![AWS](https://img.shields.io/badge/AWS-Bedrock-orange)](https://aws.amazon.com/bedrock/)
[![Python](https://img.shields.io/badge/Python-3.11+-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green)](LICENSE)

## Overview

Compliance Guardian AI is an enterprise-grade, autonomous multi-agent system built for AWS AI Agent Global Hackathon. It leverages AWS Bedrock's AgentCore, Claude 3.5 Sonnet, Amazon Q for compliance intelligence, and Amazon Nova Act for automated actions to provide comprehensive compliance and privacy management.

### Key Features

- **Multi-Framework Compliance**: GDPR, HIPAA, PCI DSS, SOX, ISO 27001, CCPA, NIST
- **6 Specialized AI Agents**: Orchestrator, Compliance, Audit, Remediation, Explainability, plus Base
- **Automated Scanning**: Code analysis, data flow mapping, resource compliance checking
- **Intelligent Remediation**: PII masking, encryption enforcement, consent management, policy injection
- **Real-time Monitoring**: Prometheus metrics, CloudWatch integration, distributed tracing
- **RESTful API**: FastAPI with async support, WebSocket for real-time updates
- **Production-Ready**: Enterprise security, audit trails, rollback support, comprehensive error handling

## Architecture

### Multi-Agent System

```

 Agent Runtime & Gateway 
 - Task scheduling & load balancing 
 - Inter-agent communication 
 - Circuit breakers & rate limiting 

 Orchestr Compliance Audit 
 ator Agent Agent 

 Remedia- Explainabil- Nova 
 tion ity Act 

```

### Components

1. **Core Infrastructure**
 - `bedrock_client.py`: AWS Bedrock AgentCore integration with Claude 3.5 Sonnet
 - `agent_runtime.py`: Multi-agent orchestration and task management
 - `agent_memory.py`: Redis-backed memory with semantic search
 - `agent_gateway.py`: Message routing and agent communication
 - `agent_identity.py`: JWT authentication and IAM integration
 - `observability.py`: Prometheus metrics and CloudWatch logging

2. **Specialized Agents**
 - `orchestrator_agent.py`: Workflow coordination and resource allocation
 - `compliance_agent.py`: Multi-framework compliance scanning
 - `audit_agent.py`: Report generation and regulatory submissions
 - `remediation_agent.py`: Automated violation remediation
 - `explainability_agent.py`: Multi-audience compliance explanations

3. **Compliance Scanners**
 - `gdpr_scanner.py`: Article-by-article GDPR compliance checking
 - `hipaa_scanner.py`: Administrative, physical, technical safeguards
 - `pci_scanner.py`: 12 PCI DSS requirements validation
 - `code_scanner.py`: Static code analysis for security/compliance
 - `data_flow_scanner.py`: Cross-border data transfer analysis

4. **Remediation Systems**
 - `pii_masker.py`: Tokenization, masking, format-preserving encryption
 - `encryption_enforcer.py`: AWS resource encryption automation
 - `consent_manager.py`: GDPR-compliant consent tracking
 - `policy_injector.py`: IAM/S3/KMS policy deployment

5. **RESTful API**
 - `main.py`: FastAPI application with lifespan management
 - `/agents`: Agent management and task submission
 - `/scans`: Compliance scanning endpoints
 - `/workflows`: Workflow execution and templates
 - `/reports`: Report generation and download
 - `/remediation`: Automated remediation and consent management
 - `/health`: Health checks and metrics

## Technology Stack

- **AI/ML**: AWS Bedrock AgentCore, Claude 3.5 Sonnet, Amazon Q, Amazon Nova Act
- **Backend**: Python 3.11+, FastAPI, Pydantic, asyncio
- **Data**: Redis (memory), SQLAlchemy (persistence), boto3 (AWS SDK)
- **Security**: cryptography, PyJWT, AWS KMS, Secrets Manager
- **Observability**: Prometheus, CloudWatch, structlog
- **Testing**: pytest, pytest-asyncio, pytest-cov

## Quick Start

### Prerequisites

- Python 3.11 or higher
- AWS Account with Bedrock access
- Redis (for agent memory)
- AWS credentials configured

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/compliance-guardian-ai.git
cd compliance-guardian-ai

# Create virtual environment
python -m venv venv
source venv/bin/activate # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export AWS_REGION=us-east-1
export AWS_BEDROCK_AGENT_ID=your-agent-id
export REDIS_URL=redis://localhost:6379
export JWT_SECRET_KEY=your-secret-key
export AMAZON_Q_APPLICATION_ID=your-q-app-id  # For Amazon Q integration
```

### Configuration

Create `.env` file:

```env
# AWS Configuration
AWS_REGION=us-east-1
AWS_BEDROCK_AGENT_ID=your-agent-id
AWS_BEDROCK_MODEL_ID=anthropic.claude-3-5-sonnet-20241022-v2:0

# Amazon Q Configuration (for compliance intelligence)
AMAZON_Q_APPLICATION_ID=your-application-id
AMAZON_Q_INDEX_ID=your-index-id  # optional
AMAZON_Q_MOCK=false  # Set to true for testing without AWS

# Redis
REDIS_URL=redis://localhost:6379

# Security
JWT_SECRET_KEY=your-secret-key-here
ENCRYPTION_KEY=your-encryption-key-here

# Observability
LOG_LEVEL=INFO
ENABLE_METRICS=true

# API
CORS_ORIGINS=["http://localhost:3000"]
```

### Run Application

```bash
# Start Redis (if not running)
redis-server

# Run FastAPI application
python -m src.api.main

# API available at: http://localhost:8000
# Docs available at: http://localhost:8000/docs
```

## Amazon Q Integration

The project now includes a complete Amazon Q client for compliance intelligence:

### Quick Start with Amazon Q

```python
from src.amazon_q import AmazonQClient, query_compliance

# Quick query using convenience function
response = query_compliance(
    query="What are GDPR requirements for data encryption?",
    framework="GDPR",
    mock=True  # Use mock mode for testing
)

print(response.get_guidance())
```

### Using the Client

```python
from src.amazon_q import AmazonQClient, AmazonQConfig

# Create client
config = AmazonQConfig.from_env()  # Load from environment
client = AmazonQClient(config)

# Query compliance guidance
response = client.query_compliance(
    query="How to implement HIPAA audit logging?",
    framework="HIPAA"
)

# Get policy interpretation
interpretation = client.get_policy_interpretation(
    policy_text="All PHI must be encrypted at rest",
    framework="HIPAA"
)

# Check specific requirement
result = client.check_requirement(
    requirement="Enable MFA for admin access",
    framework="PCI-DSS"
)

# Get remediation guidance
guidance = client.get_remediation_guidance(
    violation="S3 bucket not encrypted",
    framework="GDPR"
)
```

### Running Examples

```bash
# Run all Amazon Q examples
python examples/amazon_q_usage.py

# Set mock mode for testing
set AMAZON_Q_MOCK=true
python examples/amazon_q_usage.py
```

See `src/amazon_q/README.md` for detailed documentation and `examples/amazon_q_usage.py` for more examples.

## API Usage

### 1. Execute GDPR Compliance Workflow

```bash
curl -X POST "http://localhost:8000/api/v1/workflows/execute" \
 -H "Content-Type: application/json" \
 -d '{
 "workflow_type": "gdpr_compliance_check",
 "parameters": {
 "resource_ids": ["s3://my-bucket"],
 "scope": "full"
 }
 }'
```

Response:
```json
{
 "workflow_id": "wf_123456",
 "workflow_type": "gdpr_compliance_check",
 "status": "started",
 "timestamp": "2024-01-15T10:30:00Z"
}
```

### 2. Run Code Compliance Scan

```bash
curl -X POST "http://localhost:8000/api/v1/scans/code" \
 -H "Content-Type: application/json" \
 -d '{
 "repository_url": "https://github.com/org/repo",
 "branch": "main"
 }'
```

### 3. Generate Audit Report

```bash
curl -X POST "http://localhost:8000/api/v1/reports/generate" \
 -H "Content-Type: application/json" \
 -d '{
 "report_type": "audit",
 "framework": "gdpr",
 "format": "pdf"
 }'
```

### 4. Mask PII Data

```bash
curl -X POST "http://localhost:8000/api/v1/remediation/pii/mask" \
 -H "Content-Type: application/json" \
 -d '{
 "data": {
 "email": "user@example.com",
 "ssn": "123-45-6789",
 "name": "John Doe"
 },
 "strategy": "tokenize"
 }'
```

Response:
```json
{
 "masked_data": {
 "email": "u***@example.com",
 "ssn": "TOK_a1b2c3d4",
 "name": "J*** D***"
 },
 "masking_report": {
 "total_masked": 3,
 "reversible_count": 1
 }
}
```

### 5. Enforce Encryption

```bash
curl -X POST "http://localhost:8000/api/v1/remediation/encryption/enforce" \
 -H "Content-Type: application/json" \
 -d '{
 "resource_type": "s3",
 "resource_ids": ["my-bucket-1", "my-bucket-2"]
 }'
```

## Agent Capabilities

### Orchestrator Agent
- Workflow templates: GDPR, HIPAA, PCI, Incident Response, Full Audit
- Resource allocation and load balancing
- Multi-framework coordination
- Emergency response handling

### Compliance Agent
- Multi-framework scanning (7 frameworks)
- Real-time violation detection
- PII/PHI identification with 8 categories
- Code and data flow analysis
- Risk scoring and prioritization

### Audit Agent
- Framework-specific report generation
- Regulatory submission formatting
- Executive summaries
- Audit trail management
- Evidence collection

### Remediation Agent
- Automated violation remediation with 12 templates
- Approval workflows (single/multi-level)
- Rollback support with state snapshots
- Impact analysis
- Emergency containment

### Explainability Agent
- Multi-audience explanations (technical, executive, legal, end-user)
- Policy interpretation with LLM
- Visual aids generation
- FAQ creation
- Regulatory change tracking

## Compliance Frameworks

### GDPR (9 Principles)
- Lawfulness, fairness, transparency
- Purpose limitation
- Data minimization
- Accuracy
- Storage limitation
- Integrity and confidentiality
- Accountability
- Data subject rights (Arts 15-22)
- Cross-border transfers (Arts 44-50)

### HIPAA (3 Safeguard Types)
- Administrative safeguards (164.308)
- Physical safeguards (164.310)
- Technical safeguards (164.312)
- Breach notification (164.402-414)

### PCI DSS (12 Requirements)
- Build and maintain secure network
- Protect cardholder data
- Vulnerability management
- Access control measures
- Network monitoring and testing
- Information security policy

## Deployment

### Docker

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

```bash
docker build -t compliance-guardian-ai .
docker run -p 8000:8000 \
 -e AWS_REGION=us-east-1 \
 -e REDIS_URL=redis://redis:6379 \
 compliance-guardian-ai
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
 name: compliance-guardian
spec:
 replicas: 3
 selector:
 matchLabels:
 app: compliance-guardian
 template:
 metadata:
 labels:
 app: compliance-guardian
 spec:
 containers:
 - name: api
 image: compliance-guardian-ai:latest
 ports:
 - containerPort: 8000
 env:
 - name: AWS_REGION
 value: us-east-1
 - name: REDIS_URL
 value: redis://redis:6379
 livenessProbe:
 httpGet:
 path: /api/v1/health/live
 port: 8000
 readinessProbe:
 httpGet:
 path: /api/v1/health/ready
 port: 8000
```

### AWS ECS/Fargate

See `infrastructure/cloudformation/` for CloudFormation templates.

## Security

- **Encryption**: AES-256 for data at rest, TLS 1.2+ for data in transit
- **Authentication**: JWT tokens with configurable expiration
- **Authorization**: IAM role-based access control
- **Audit Trails**: All actions logged with correlation IDs
- **Secrets Management**: AWS Secrets Manager integration
- **PII Protection**: Automatic detection and masking
- **Rate Limiting**: Circuit breakers and request throttling

## Monitoring

### Prometheus Metrics

- `compliance_scans_total`: Total compliance scans executed
- `compliance_violations_detected`: Violations detected by severity
- `remediation_actions_total`: Remediation actions executed
- `agent_tasks_duration_seconds`: Task execution duration
- `agent_memory_entries`: Memory entries per agent

### CloudWatch Logs

- Structured JSON logging with correlation IDs
- PII filtering before log output
- Configurable log levels
- Log retention policies

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test suite
pytest tests/unit/agents/
pytest tests/integration/
```

## Contributing

1. Fork repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## License

Apache License 2.0 - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- **AWS Bedrock Team**: For AgentCore and Claude 3.5 Sonnet
- **Amazon Q Team**: For compliance intelligence capabilities
- **Amazon Nova Team**: For automated action execution
- **AWS AI Agent Global Hackathon**: For the opportunity

## Support

- Documentation: `/docs`
- Issues: GitHub Issues
- Email: support@compliance-guardian.ai

## Project Statistics

- **Total Lines of Code**: ~15,000+
- **Components**: 30+ modules
- **AI Agents**: 6 specialized agents
- **Compliance Scanners**: 5 frameworks
- **Remediation Systems**: 4 automated systems
- **API Endpoints**: 40+ routes
- **Test Coverage**: 85%+

---

**Built for AWS AI Agent Global Hackathon 2024** 
*Securing compliance, protecting privacy, powered by AWS*
