# Deployment Guide - Compliance Guardian AI

## Overview

This guide walks you through deploying Compliance Guardian AI to AWS from scratch.

**Deployment Time**: ~30 minutes 
**Cost**: ~$20-50/month (based on usage) 
**Prerequisites**: AWS account with admin access

---

## Table of Contents

1. [Pre-Deployment Checklist](#pre-deployment-checklist)
2. [AWS Account Setup](#aws-account-setup)
3. [Enable Amazon Bedrock](#enable-amazon-bedrock)
4. [Deploy Infrastructure](#deploy-infrastructure)
5. [Deploy Lambda Functions](#deploy-lambda-functions)
6. [Test Deployment](#test-deployment)
7. [Post-Deployment Configuration](#post-deployment-configuration)
8. [Troubleshooting](#troubleshooting)

---

## Pre-Deployment Checklist

Before starting, ensure you have:

- [[]] AWS account with admin privileges
- [[]] Python 3.11+ installed
- [[]] AWS CLI installed and configured
- [[]] Git installed
- [[]] Basic understanding of AWS services

### Install AWS CLI

**Windows**:
```cmd
msiexec.exe /i https://awscli.amazonaws.com/AWSCLIV2.msi
```

**Linux/Mac**:
```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
```

### Verify Installation

```bash
aws --version
python --version
git --version
```

---

## AWS Account Setup

### Step 1: Configure AWS Credentials

```bash
aws configure
```

Provide:
- **AWS Access Key ID**: Your access key
- **AWS Secret Access Key**: Your secret key
- **Default region**: `us-east-1` (recommended)
- **Output format**: `json`

### Step 2: Verify Credentials

```bash
aws sts get-caller-identity
```

Expected output:
```json
{
 "UserId": "AIDAI...",
 "Account": "943598056704",
 "Arn": "arn:aws:iam::943598056704:user/your-username"
}
```

### Step 3: Check IAM Permissions

Required permissions:
- `iam:CreateRole`
- `lambda:CreateFunction`
- `apigateway:*`
- `dynamodb:CreateTable`
- `s3:CreateBucket`
- `bedrock:InvokeModel`
- `cloudformation:CreateStack`

---

## Enable Amazon Bedrock

### Step 1: Run Bedrock Setup Script

```bash
python enable_bedrock.py
```

This script:
1. Checks Bedrock availability in your region
2. Requests model access if needed
3. Verifies Nova Pro and Claude 3.5 Sonnet access

### Step 2: Request Model Access Manually

If automated script fails:

1. Go to [AWS Bedrock Console](https://console.aws.amazon.com/bedrock)
2. Navigate to **Model access**
3. Click **Request model access**
4. Select:
 - [[]] Amazon Nova Pro
 - [[]] Claude 3.5 Sonnet v2
5. Agree to terms and submit

**Note**: Model access approval is usually instant but can take up to 24 hours.

### Step 3: Verify Model Access

```bash
python test_bedrock.py
```

Expected output:
```
[[]] Amazon Nova Pro: Available
[[]] Claude 3.5 Sonnet v2: Available
```

### Step 4: Submit Anthropic Form (if using Claude)

For production use of Claude models:

```bash
python submit_anthropic_form.py
```

Follow the prompts to complete the Anthropic use case form.

---

## Deploy Infrastructure

### Option 1: Automated Deployment (Windows)

```cmd
python deploy_windows.py
```

This script handles:
- [[]] IAM role creation
- [[]] DynamoDB table setup
- [[]] S3 bucket creation
- [[]] Lambda function deployment
- [[]] API Gateway configuration
- [[]] CloudWatch logging setup

### Option 2: Manual Deployment

#### Step 1: Create IAM Roles

```bash
aws iam create-role \
 --role-name ComplianceScanExecutionRole \
 --assume-role-policy-document file://infrastructure/iam/trust-policy.json
```

Attach policies:
```bash
aws iam attach-role-policy \
 --role-name ComplianceScanExecutionRole \
 --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

aws iam put-role-policy \
 --role-name ComplianceScanExecutionRole \
 --policy-name BedrockAccess \
 --policy-document file://infrastructure/iam/bedrock-policy.json
```

#### Step 2: Create DynamoDB Tables

```bash
python setup_infrastructure.py --tables-only
```

Creates:
- `compliance_scans`
- `compliance_policies`
- `violations`
- `compliance_metrics`
- `remediation_history`

#### Step 3: Create S3 Buckets

```bash
python setup_infrastructure.py --s3-only
```

Creates:
- `compliance-reports-{account_id}`
- `compliance-policies-{account_id}`
- `compliance-evidence-{account_id}`

#### Step 4: Deploy Lambda Functions

```bash
python deploy_lambda.py
```

Deploys:
- `compliance-scan-handler`
- `compliance-policy-engine`
- `compliance-remediation`
- `compliance-risk-assessment`
- `compliance-report-generation`
- `compliance-metrics`

#### Step 5: Create API Gateway

```bash
python setup_infrastructure.py --api-only
```

Creates REST API with:
- `/scan` POST endpoint
- CloudWatch logging
- CORS enabled

### Option 3: CloudFormation (Recommended for Production)

```bash
aws cloudformation create-stack \
 --stack-name compliance-guardian \
 --template-body file://infrastructure/cloudformation/main.yaml \
 --capabilities CAPABILITY_IAM
```

Monitor deployment:
```bash
aws cloudformation describe-stacks --stack-name compliance-guardian
```

---

## Deploy Lambda Functions

### Step 1: Package Lambda Code

```bash
cd src
zip -r ../lambda.zip .
cd ..
```

### Step 2: Upload to Lambda

```bash
aws lambda update-function-code \
 --function-name compliance-scan-handler \
 --zip-file fileb://lambda.zip
```

### Step 3: Configure Environment Variables

```bash
aws lambda update-function-configuration \
 --function-name compliance-scan-handler \
 --environment Variables="{
 MODEL_ID=us.amazon.nova-pro-v1:0,
 FALLBACK_MODEL_ID=us.anthropic.claude-3-5-sonnet-20241022-v2:0,
 DYNAMODB_TABLE=compliance_scans,
 LOG_LEVEL=INFO
 }"
```

### Step 4: Set Memory and Timeout

```bash
aws lambda update-function-configuration \
 --function-name compliance-scan-handler \
 --memory-size 2048 \
 --timeout 300
```

---

## Test Deployment

### Step 1: Get API Endpoint

```bash
aws apigateway get-rest-apis
```

Find your API and note the endpoint:
```
https://{api-id}.execute-api.us-east-1.amazonaws.com/production
```

### Step 2: Test with cURL

```bash
curl -X POST https://YOUR-API-ENDPOINT/scan \
 -H "Content-Type: application/json" \
 -d '{
 "code": "def process_payment(card, cvv): db.save({\"card\": card, \"cvv\": cvv})",
 "scan_type": "pci-dss"
 }'
```

### Step 3: Test with Python Script

```bash
python test_scan_endpoint.py
```

Expected output:
```
[[]] API Endpoint: https://...
[[]] Status Code: 200
[[]] Scan ID: scan-20251017-...
[[]] Violations Found: 2
[[]] Compliance Score: 45
```

### Step 4: Run Complete Workflow Test

```bash
python test_complete_workflow.py
```

This tests:
- [[]] GDPR scan
- [[]] HIPAA scan
- [[]] PCI-DSS scan
- [[]] Comprehensive scan
- [[]] Report generation

---

## Post-Deployment Configuration

### Step 1: Update Configuration File

Edit `infrastructure_config.json`:

```json
{
 "api_endpoint": "https://YOUR-API-ENDPOINT/production/scan",
 "region": "us-east-1",
 "account_id": "YOUR-ACCOUNT-ID",
 "lambda_functions": {
 "scan_handler": "compliance-scan-handler"
 }
}
```

### Step 2: Configure CloudWatch Alarms

```bash
aws cloudwatch put-metric-alarm \
 --alarm-name compliance-scan-errors \
 --comparison-operator GreaterThanThreshold \
 --evaluation-periods 2 \
 --metric-name Errors \
 --namespace AWS/Lambda \
 --period 300 \
 --statistic Sum \
 --threshold 5 \
 --alarm-description "Alert on Lambda errors"
```

### Step 3: Set Up SNS Notifications (Optional)

```bash
aws sns create-topic --name compliance-alerts

aws sns subscribe \
 --topic-arn arn:aws:sns:us-east-1:YOUR-ACCOUNT:compliance-alerts \
 --protocol email \
 --notification-endpoint your-email@example.com
```

### Step 4: Enable API Gateway Logging

```bash
aws apigateway update-stage \
 --rest-api-id YOUR-API-ID \
 --stage-name production \
 --patch-operations op=replace,path=/accessLogSettings/destinationArn,value=arn:aws:logs:us-east-1:YOUR-ACCOUNT:log-group:api-gateway-logs
```

### Step 5: Configure CORS (if needed)

```bash
python configure_cors.py
```

---

## Cost Estimation

### Monthly Costs (Moderate Usage)

| Service | Usage | Cost |
|---------|-------|------|
| **Lambda** | 10,000 requests/month | $2.00 |
| **API Gateway** | 10,000 requests | $0.35 |
| **Bedrock** | 1M input tokens, 100K output | $15.00 |
| **DynamoDB** | On-demand, 10K reads/writes | $2.50 |
| **S3** | 1 GB storage, 1K requests | $0.50 |
| **CloudWatch** | Logs and metrics | $1.00 |
| **Total** | | **~$21.35/month** |

### Cost Optimization Tips

1. **Use Reserved Concurrency**: For predictable workloads
2. **Enable S3 Lifecycle Policies**: Auto-delete old reports
3. **Use DynamoDB On-Demand**: Only pay for what you use
4. **Set TTL on DynamoDB**: Auto-delete old scan records
5. **Use CloudWatch Log Retention**: Delete old logs after 30 days

---

## Monitoring and Maintenance

### CloudWatch Dashboard

Create a custom dashboard:

```bash
python create_dashboard.py
```

Metrics to monitor:
- Lambda invocation count
- Lambda error rate
- API Gateway latency
- Bedrock token usage
- DynamoDB read/write capacity

### Log Analysis

View Lambda logs:
```bash
aws logs tail /aws/lambda/compliance-scan-handler --follow
```

Filter errors:
```bash
aws logs filter-log-events \
 --log-group-name /aws/lambda/compliance-scan-handler \
 --filter-pattern "ERROR"
```

### Regular Maintenance Tasks

**Weekly**:
- Review CloudWatch metrics
- Check error rates
- Verify Bedrock model availability

**Monthly**:
- Review cost reports
- Update Lambda functions
- Clean up old S3 objects
- Review DynamoDB capacity

**Quarterly**:
- Security audit
- Update compliance policies
- Review IAM permissions
- Update dependencies

---

## Troubleshooting

### Issue: Lambda Timeout

**Symptoms**: Scans fail after 30 seconds

**Solution**:
```bash
aws lambda update-function-configuration \
 --function-name compliance-scan-handler \
 --timeout 300
```

### Issue: Bedrock Access Denied

**Symptoms**: `AccessDeniedException` when calling Bedrock

**Solution**:
1. Verify model access in Bedrock console
2. Check IAM role permissions
3. Wait up to 24 hours for model access approval

### Issue: DynamoDB Throttling

**Symptoms**: `ProvisionedThroughputExceededException`

**Solution**:
```bash
aws dynamodb update-table \
 --table-name compliance_scans \
 --billing-mode PAY_PER_REQUEST
```

### Issue: API Gateway 502 Error

**Symptoms**: Bad Gateway error

**Solution**:
1. Check Lambda function logs
2. Verify Lambda execution role
3. Test Lambda directly:
```bash
aws lambda invoke \
 --function-name compliance-scan-handler \
 --payload '{"code": "test"}' \
 response.json
```

### Issue: High Costs

**Symptoms**: Unexpected AWS bill

**Solution**:
1. Check CloudWatch metrics for usage spikes
2. Review Bedrock token consumption
3. Enable AWS Cost Anomaly Detection
4. Set up billing alerts

---

## Redeployment

### Update Lambda Code

```bash
python deploy_lambda.py --update
```

### Update Infrastructure

```bash
python setup_infrastructure.py --update
```

### Switch Models

To switch from Nova Pro to Claude:

```bash
python switch_to_nova.py --model claude
```

Or update environment variable:
```bash
aws lambda update-function-configuration \
 --function-name compliance-scan-handler \
 --environment Variables="{MODEL_ID=us.anthropic.claude-3-5-sonnet-20241022-v2:0}"
```

---

## Rollback Procedure

If deployment fails:

### Rollback Lambda

```bash
aws lambda update-function-code \
 --function-name compliance-scan-handler \
 --s3-bucket compliance-lambda-backups \
 --s3-key backups/lambda-v1.0.zip
```

### Rollback CloudFormation

```bash
aws cloudformation update-stack \
 --stack-name compliance-guardian \
 --use-previous-template
```

### Rollback Database

DynamoDB point-in-time recovery:
```bash
aws dynamodb restore-table-to-point-in-time \
 --source-table-name compliance_scans \
 --target-table-name compliance_scans_restored \
 --restore-date-time 2025-10-17T12:00:00Z
```

---

## Security Hardening (Production)

### 1. Enable API Authentication

```bash
python configure_api_auth.py
```

### 2. Restrict IAM Permissions

Use least-privilege principle:
```json
{
 "Effect": "Allow",
 "Action": [
 "bedrock:InvokeModel"
 ],
 "Resource": [
 "arn:aws:bedrock:us-east-1::foundation-model/us.amazon.nova-pro-v1:0"
 ]
}
```

### 3. Enable VPC for Lambda

```bash
aws lambda update-function-configuration \
 --function-name compliance-scan-handler \
 --vpc-config SubnetIds=subnet-xxx,SecurityGroupIds=sg-xxx
```

### 4. Enable CloudTrail

```bash
aws cloudtrail create-trail \
 --name compliance-audit-trail \
 --s3-bucket-name compliance-audit-logs
```

### 5. Encrypt Environment Variables

```bash
aws lambda update-function-configuration \
 --function-name compliance-scan-handler \
 --environment Variables="{...}" \
 --kms-key-arn arn:aws:kms:us-east-1:YOUR-ACCOUNT:key/YOUR-KMS-KEY
```

---

## Multi-Region Deployment (Advanced)

### Step 1: Deploy to Secondary Region

```bash
export AWS_REGION=eu-west-1
python deploy_windows.py
```

### Step 2: Set Up Route 53

```bash
python setup_multi_region.py
```

### Step 3: Enable DynamoDB Global Tables

```bash
aws dynamodb create-global-table \
 --global-table-name compliance_scans \
 --replication-group RegionName=us-east-1 RegionName=eu-west-1
```

---

## Backup and Disaster Recovery

### Automated Backups

```bash
python setup_backups.py
```

Configures:
- DynamoDB point-in-time recovery
- S3 versioning
- Lambda code backups
- Infrastructure as Code backups

### Recovery Testing

```bash
python test_disaster_recovery.py
```

Tests:
- Lambda function restoration
- DynamoDB table recovery
- S3 bucket restoration
- API Gateway reconfiguration

---

## Next Steps

After successful deployment:

1. [[]] **Test thoroughly**: Run `test_complete_workflow.py`
2. **Set up monitoring**: Configure CloudWatch dashboard
3. **Enable alerts**: Set up SNS notifications
4. **Update docs**: Document your specific configuration
5. **Run demos**: Test with `demo.py` and `demo_animated.py`

---

## Support Resources

- **AWS Documentation**: [docs.aws.amazon.com](https://docs.aws.amazon.com)
- **Bedrock Guide**: [Amazon Bedrock User Guide](https://docs.aws.amazon.com/bedrock/)
- **Project Issues**: GitHub Issues
- **AWS Support**: Available 24/7 (based on support plan)

---

## Deployment Checklist

- [ ] AWS account configured
- [ ] Bedrock models enabled
- [ ] IAM roles created
- [ ] DynamoDB tables deployed
- [ ] S3 buckets created
- [ ] Lambda functions deployed
- [ ] API Gateway configured
- [ ] CloudWatch logging enabled
- [ ] Test scans successful
- [ ] Monitoring dashboard created
- [ ] Cost alerts configured
- [ ] Documentation updated
- [ ] Team notified

---

**Deployment Complete! **

Your Compliance Guardian AI system is now live and ready to scan for violations!
