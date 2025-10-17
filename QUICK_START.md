# [LAUNCH] Quick Start - Compliance Guardian AI

## Minimum Requirements to Run

### 1. AWS Account (REQUIRED)
[OK] **Must Have:**
- AWS account with credit card
- **Amazon Bedrock access to:**
  - Claude 3.5 Sonnet v2
  - Amazon Nova Act
- IAM user with admin permissions

[WARNING] **Enable Bedrock:**
```
AWS Console → Bedrock → Model Access → Request Access
```

### 2. Local Environment
```bash
# Install Python 3.11+
python --version

# Create virtual environment
python -m venv venv

# Activate (Windows)
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### 3. AWS Credentials
```bash
# Configure AWS CLI
aws configure

# Verify Bedrock access
aws bedrock list-foundation-models --region us-east-1
```

### 4. Setup AWS Resources
```bash
# Run setup script (Git Bash on Windows)
bash scripts/setup_aws_resources.sh production
```

Creates: S3 buckets, DynamoDB tables, IAM roles, KMS keys

### 5. Configure Environment
```bash
# Copy template
cp .env.example .env

# Edit .env with your AWS credentials
notepad .env  # Windows
nano .env     # Mac/Linux
```

**Required fields:**
```bash
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
BEDROCK_MODEL_ID=anthropic.claude-3-5-sonnet-20241022-v2:0
```

### 6. Test Installation
```bash
# Run unit tests
.\venv\Scripts\pytest tests/unit/ -v

# Should see: 20 passed [OK]
```

### 7. Run the System
```bash
# Start API server
uvicorn src.api.main:app --reload --port 8000

# Run example scan (new terminal)
python examples/run_gdpr_scan.py
```

## Optional (But Recommended)

### GitHub Integration
```bash
# Get token: https://github.com/settings/tokens
GITHUB_TOKEN=ghp_...
```

### Email Notifications
```bash
# Gmail app password: https://myaccount.google.com/apppasswords
SMTP_HOST=smtp.gmail.com
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=<16-char-password>
```

### Slack Alerts
```bash
# Webhook: https://api.slack.com/messaging/webhooks
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

## Estimated Costs

**Development (Free Tier):**
- $15-25/month (mostly Bedrock API calls)

**Production:**
- $77-265/month (depends on usage)

## Quick Commands Reference

```bash
# Activate environment
.\venv\Scripts\Activate.ps1

# Run tests
pytest tests/unit/ -v --no-cov

# Start API
uvicorn src.api.main:app --reload

# Run GDPR scan
python examples/run_gdpr_scan.py

# Run HIPAA scan
python examples/run_hipaa_scan.py

# Deploy to AWS
bash scripts/deploy.sh production

# View API docs
http://localhost:8000/docs

# View dashboard
http://localhost:8000/dashboard
```

## Troubleshooting

**"Bedrock not accessible"**
→ AWS Console → Bedrock → Model Access → Request

**"No module named 'src'"**
→ Run from project root directory

**"AWS credentials not configured"**
→ Run `aws configure`

**"DynamoDB table not found"**
→ Run `bash scripts/setup_aws_resources.sh production`

## What You DON'T Need

[ERROR] Local PostgreSQL database (DynamoDB is used)
[ERROR] Local Redis server (optional for caching)
[ERROR] Docker (optional for deployment)
[ERROR] Kubernetes (optional for scaling)
[ERROR] MongoDB (DynamoDB handles all storage)

## Full Setup Guide

For complete documentation see: `SETUP_GUIDE.md`

## Current Status

[OK] All dependencies installed (if you followed steps above)
[OK] 20/20 unit tests passing
[OK] No syntax errors in codebase
[OK] All Python imports working

**Next Step:** Configure your AWS account and run setup script!
