# Architecture Documentation - Compliance Guardian AI

## System Overview

Compliance Guardian AI is a cloud-native, AI-powered compliance monitoring system built on AWS. It leverages Amazon Bedrock's foundation models to analyze code and infrastructure for regulatory compliance violations.

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLIENT LAYER                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │   CLI    │  │ Web App  │  │   API    │  │   SDK    │       │
│  │  Tool    │  │Dashboard │  │ Clients  │  │Libraries │       │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘       │
└───────┼─────────────┼─────────────┼─────────────┼──────────────┘
        │             │             │             │
        └─────────────┴─────────────┴─────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                      API GATEWAY LAYER                           │
│  ┌────────────────────────────────────────────────────────┐    │
│  │  Amazon API Gateway (REST API)                          │    │
│  │  - Request Validation                                   │    │
│  │  - Rate Limiting                                        │    │
│  │  - CloudWatch Logging                                   │    │
│  └─────────────────────┬──────────────────────────────────┘    │
└────────────────────────┼───────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                     COMPUTE LAYER (AWS Lambda)                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │Scan Handler  │  │Policy Engine │  │Report Gen    │         │
│  │Lambda        │  │Lambda        │  │Lambda        │         │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘         │
│         │                  │                  │                  │
│  ┌──────┴───────┐  ┌──────┴───────┐  ┌──────┴───────┐         │
│  │Remediation   │  │Risk Assessment│  │Metrics       │         │
│  │Lambda        │  │Lambda        │  │Lambda        │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                      AI/ML LAYER (Amazon Bedrock)                │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Amazon Bedrock Foundation Models                        │   │
│  │  ┌────────────────┐        ┌──────────────────┐        │   │
│  │  │ Amazon Nova    │        │ Claude 3.5       │        │   │
│  │  │ Pro v1         │───────▶│ Sonnet v2        │        │   │
│  │  │ (Primary)      │ Fallback│ (Secondary)     │        │   │
│  │  └────────────────┘        └──────────────────┘        │   │
│  │                                                           │   │
│  │  • Code Analysis            • Violation Detection        │   │
│  │  • Pattern Recognition      • Remediation Generation     │   │
│  │  • Risk Assessment          • Report Synthesis           │   │
│  └─────────────────────────────────────────────────────────┘   │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                       STORAGE LAYER                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │  DynamoDB    │  │  S3 Buckets  │  │ CloudWatch   │         │
│  │  Tables      │  │              │  │  Logs        │         │
│  │  • Scans     │  │  • Reports   │  │              │         │
│  │  • Policies  │  │  • Policies  │  │              │         │
│  │  • Violations│  │  • Evidence  │  │              │         │
│  │  • Metrics   │  │              │  │              │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
└─────────────────────────────────────────────────────────────────┘
```

---

## Core Components

### 1. API Gateway Layer

**Purpose**: Manages all incoming API requests and routes to appropriate Lambda functions.

**Components**:
- **REST API**: Main entry point for all client requests
- **Request Validation**: JSON schema validation
- **Authentication**: IAM roles and API keys
- **Rate Limiting**: Prevents abuse
- **CORS**: Cross-origin resource sharing
- **CloudWatch Integration**: Request logging

**Configuration**:
```json
{
  "name": "compliance-guardian-api",
  "protocol": "REST",
  "endpoint": "https://gluwdyp4ii.execute-api.us-east-1.amazonaws.com/production",
  "authentication": "AWS_IAM",
  "throttling": {
    "rate": 10000,
    "burst": 5000
  }
}
```

---

### 2. Compute Layer (AWS Lambda)

#### 2.1 Scan Handler Lambda

**Purpose**: Orchestrates compliance scans.

**Runtime**: Python 3.11  
**Memory**: 2048 MB  
**Timeout**: 300 seconds

**Responsibilities**:
1. Parse scan requests
2. Load appropriate compliance policies
3. Call Bedrock for AI analysis
4. Detect violations
5. Generate compliance scores
6. Return structured results

**Code Flow**:
```python
def lambda_handler(event, context):
    # 1. Parse request
    request = parse_request(event)
    
    # 2. Load policies
    policies = load_policies(request.frameworks)
    
    # 3. AI Analysis
    analysis = bedrock_analyze(request.code, policies)
    
    # 4. Detect violations
    violations = detect_violations(analysis, policies)
    
    # 5. Calculate score
    score = calculate_compliance_score(violations)
    
    # 6. Store results
    store_scan_results(violations, score)
    
    # 7. Return response
    return format_response(violations, score)
```

#### 2.2 Policy Engine Lambda

**Purpose**: Manages compliance policies and rules.

**Capabilities**:
- Policy CRUD operations
- Policy versioning
- Rule interpretation
- Custom policy support

#### 2.3 Remediation Lambda

**Purpose**: Generates automated remediation suggestions.

**AI Models Used**:
- Amazon Nova Pro (code generation)
- Claude 3.5 Sonnet (explanation)

#### 2.4 Risk Assessment Lambda

**Purpose**: Evaluates risk levels and impacts.

**Metrics**:
- Violation severity scoring
- Business impact analysis
- Compliance gap identification
- Risk prioritization

#### 2.5 Report Generation Lambda

**Purpose**: Creates compliance reports.

**Formats**:
- JSON (programmatic)
- PDF (human-readable)
- CSV (data export)
- HTML (web viewing)

#### 2.6 Metrics Lambda

**Purpose**: Collects and aggregates compliance metrics.

**Tracked Metrics**:
- Scan counts
- Violation trends
- Compliance scores over time
- Framework coverage
- Response times

---

### 3. AI/ML Layer (Amazon Bedrock)

#### 3.1 Primary Model: Amazon Nova Pro

**Model ID**: `us.amazon.nova-pro-v1:0`

**Use Cases**:
- Code analysis and understanding
- Violation detection
- Pattern recognition
- Compliance scoring

**Configuration**:
```json
{
  "modelId": "us.amazon.nova-pro-v1:0",
  "temperature": 0.1,
  "maxTokens": 4096,
  "topP": 0.9
}
```

**Prompt Structure**:
```
You are a compliance expert. Analyze the following code for {framework} violations:

CODE:
{code}

POLICIES:
{policies}

Identify:
1. Specific violations with line numbers
2. Severity levels (critical/high/medium/low)
3. Remediation recommendations
4. Compliance score (0-100)
```

#### 3.2 Secondary Model: Claude 3.5 Sonnet v2

**Model ID**: `us.anthropic.claude-3-5-sonnet-20241022-v2:0`

**Use Cases**:
- Fallback for Nova Pro
- Complex reasoning tasks
- Detailed explanations
- Multi-step remediation

**When to Use**:
- Nova Pro unavailable
- Complex multi-framework analysis
- Detailed audit reports

---

### 4. Storage Layer

#### 4.1 DynamoDB Tables

**Table: compliance_scans**
- **Primary Key**: scan_id (string)
- **Sort Key**: timestamp (number)
- **Attributes**: scan_type, status, results, violations
- **TTL**: 90 days
- **Read Capacity**: 5 units
- **Write Capacity**: 5 units

**Table: compliance_policies**
- **Primary Key**: policy_id (string)
- **Sort Key**: version (number)
- **Attributes**: framework, rules, severity_weights
- **Versioning**: Enabled

**Table: violations**
- **Primary Key**: violation_id (string)
- **Sort Key**: scan_id (string)
- **GSI**: framework-severity-index
- **Attributes**: framework, severity, type, remediation

**Table: compliance_metrics**
- **Primary Key**: metric_date (string)
- **Sort Key**: metric_type (string)
- **Attributes**: scan_count, avg_score, violations_by_severity

**Table: remediation_history**
- **Primary Key**: remediation_id (string)
- **Sort Key**: applied_timestamp (number)
- **Attributes**: violation_id, status, outcome

#### 4.2 S3 Buckets

**Bucket: compliance-reports-{account_id}**
- **Purpose**: Store compliance reports
- **Lifecycle**: 365 days retention
- **Encryption**: AES-256
- **Versioning**: Enabled

**Bucket: compliance-policies-{account_id}**
- **Purpose**: Store policy JSON files
- **Versioning**: Enabled
- **Access**: Lambda execution role

**Bucket: compliance-evidence-{account_id}**
- **Purpose**: Store scan evidence and logs
- **Lifecycle**: 180 days retention
- **Encryption**: AES-256

#### 4.3 CloudWatch Logs

**Log Groups**:
- `/aws/lambda/compliance-scan-handler`
- `/aws/lambda/compliance-remediation`
- `/aws/apigateway/compliance-guardian-api`

**Retention**: 30 days

---

## Data Flow

### Scan Request Flow

```
1. Client → API Gateway
   - HTTP POST /scan
   - JSON payload with code and scan_type

2. API Gateway → Scan Handler Lambda
   - Validates request
   - Routes to Lambda

3. Scan Handler → DynamoDB
   - Loads compliance policies
   - Retrieves historical data

4. Scan Handler → Amazon Bedrock
   - Sends code + policies
   - Requests AI analysis

5. Bedrock → Scan Handler
   - Returns violations
   - Provides recommendations

6. Scan Handler → DynamoDB
   - Stores scan results
   - Updates metrics

7. Scan Handler → S3
   - Saves full report

8. Scan Handler → API Gateway
   - Returns JSON response

9. API Gateway → Client
   - HTTP 200 + results
```

---

## Security Architecture

### Authentication & Authorization

**IAM Roles**:
- `ComplianceScanExecutionRole`: Lambda execution
- `ComplianceAPIRole`: API Gateway invocation
- `ComplianceStorageRole`: S3 and DynamoDB access

**Policies**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel",
        "dynamodb:PutItem",
        "dynamodb:GetItem",
        "s3:PutObject"
      ],
      "Resource": "*"
    }
  ]
}
```

### Data Encryption

**At Rest**:
- DynamoDB: AWS managed encryption
- S3: AES-256 server-side encryption
- CloudWatch Logs: Encrypted

**In Transit**:
- TLS 1.2+ for all API calls
- HTTPS only

### Network Security

**VPC Configuration**: (Production)
- Private subnets for Lambda
- NAT Gateway for outbound
- VPC endpoints for AWS services

---

## Scalability

### Auto-Scaling

**Lambda Concurrency**:
- Reserved: 10 instances
- Max: 1000 instances
- Scales automatically based on demand

**DynamoDB**:
- On-demand capacity mode
- Auto-scales read/write capacity

**API Gateway**:
- Handles 10,000 requests/second
- Regional deployment

---

## Monitoring & Observability

### CloudWatch Metrics

**Lambda Metrics**:
- Invocations
- Duration
- Errors
- Throttles

**API Gateway Metrics**:
- Request count
- Latency
- 4xx/5xx errors

**Custom Metrics**:
- Scans per framework
- Violations by severity
- Compliance scores

### Alarms

```python
{
  "ErrorRate": {
    "threshold": 5,
    "period": 300,
    "evaluation_periods": 2
  },
  "HighLatency": {
    "threshold": 10000,
    "period": 60,
    "evaluation_periods": 3
  }
}
```

---

## Deployment Architecture

### Multi-Region (Future)

```
┌─────────────────────────────────────────────┐
│           Route 53 (DNS)                    │
│     compliance-guardian.ai                  │
└─────────────┬───────────────────────────────┘
              │
       ┌──────┴──────┐
       │             │
       ▼             ▼
┌────────────┐  ┌────────────┐
│ us-east-1  │  │ eu-west-1  │
│  (Primary) │  │ (Secondary)│
│            │  │            │
│  API GW    │  │  API GW    │
│  Lambda    │  │  Lambda    │
│  DynamoDB  │  │  DynamoDB  │
│  Global    │  │  Global    │
│  Tables    │  │  Tables    │
└────────────┘  └────────────┘
```

---

## Performance Optimization

### Caching Strategy

**API Gateway Cache**:
- Cache TTL: 300 seconds
- Cache key: request body hash

**Lambda Layer**:
- Policy caching (in-memory)
- Model response caching

### Cold Start Mitigation

- Provisioned concurrency: 5 instances
- Lambda layer for shared dependencies
- Optimized import statements

---

## Disaster Recovery

**Backup Strategy**:
- DynamoDB: Point-in-time recovery (enabled)
- S3: Versioning + cross-region replication
- Lambda: Infrastructure as Code (CloudFormation)

**RTO (Recovery Time Objective)**: 1 hour  
**RPO (Recovery Point Objective)**: 5 minutes

---

## Technology Stack Summary

| Layer | Technology | Purpose |
|-------|-----------|---------|
| API | API Gateway | REST API management |
| Compute | AWS Lambda | Serverless execution |
| AI/ML | Amazon Bedrock | Foundation models |
| Storage | DynamoDB | NoSQL database |
| Storage | S3 | Object storage |
| Monitoring | CloudWatch | Logging and metrics |
| Security | IAM | Access control |
| IaC | CloudFormation | Infrastructure deployment |

---

## Design Principles

1. **Serverless-First**: No servers to manage
2. **AI-Native**: Bedrock at the core
3. **Event-Driven**: Asynchronous processing
4. **Scalable**: Auto-scales with demand
5. **Secure**: Encryption everywhere
6. **Observable**: Full monitoring stack
7. **Cost-Optimized**: Pay-per-use model

---

## Future Enhancements

- [ ] Multi-region deployment
- [ ] Real-time streaming analysis
- [ ] GraphQL API support
- [ ] Custom ML model training
- [ ] Automated remediation execution
- [ ] Compliance-as-Code SDK
- [ ] Integration marketplace

---

## References

- [AWS Lambda Documentation](https://docs.aws.amazon.com/lambda/)
- [Amazon Bedrock Guide](https://docs.aws.amazon.com/bedrock/)
- [API Gateway Best Practices](https://docs.aws.amazon.com/apigateway/latest/developerguide/best-practices.html)
- [DynamoDB Design Patterns](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/best-practices.html)
