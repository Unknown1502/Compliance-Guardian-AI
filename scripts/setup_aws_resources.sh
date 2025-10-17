#!/bin/bash

################################################################################
# AWS Infrastructure Setup Script for Compliance Guardian AI
# 
# This script provisions ALL AWS resources needed for the multi-agent system:
# - Bedrock model access verification
# - S3 buckets (artifacts, dashboard, logs)
# - DynamoDB tables (violations, audit logs, agent memory, reports)
# - KMS encryption keys
# - IAM roles for 5 agents with least-privilege permissions
# - Secrets Manager for API keys
# - CloudWatch log groups
# - API Gateway REST endpoints
# - VPC and networking components
# - Terraform infrastructure deployment
#
# Usage: ./scripts/setup_aws_resources.sh [--region us-east-1] [--environment prod]
################################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration
AWS_REGION="${AWS_REGION:-us-east-1}"
ENVIRONMENT="${1:-production}"
PROJECT_NAME="compliance-guardian-ai"
TERRAFORM_DIR="infrastructure/terraform"
BEDROCK_MODEL_ID="anthropic.claude-3-5-sonnet-20241022-v2:0"
NOVA_MODEL_ID="amazon.nova-act-v1:0"

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}  Compliance Guardian AI - AWS Setup${NC}"
echo -e "${BLUE}  Environment: ${ENVIRONMENT}${NC}"
echo -e "${BLUE}  Region: ${AWS_REGION}${NC}"
echo -e "${BLUE}================================================${NC}\n"

################################################################################
# Step 1: Check Prerequisites
################################################################################
echo -e "${YELLOW}[1/12] Checking Prerequisites...${NC}"

# Check AWS CLI
if ! command -v aws &> /dev/null; then
    echo -e "${RED}[ERROR] AWS CLI not found. Please install: https://aws.amazon.com/cli/${NC}"
    exit 1
fi
echo -e "${GREEN}[OK] AWS CLI installed: $(aws --version)${NC}"

# Check Terraform
if ! command -v terraform &> /dev/null; then
    echo -e "${RED}[ERROR] Terraform not found. Please install: https://www.terraform.io/downloads${NC}"
    exit 1
fi
echo -e "${GREEN}[OK] Terraform installed: $(terraform version -json | grep -o '"terraform_version":"[^"]*' | cut -d'"' -f4)${NC}"

# Check jq for JSON parsing
if ! command -v jq &> /dev/null; then
    echo -e "${YELLOW}[WARNING] jq not found. Installing...${NC}"
    # Attempt to install jq (varies by OS)
    if command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y jq
    elif command -v yum &> /dev/null; then
        sudo yum install -y jq
    else
        echo -e "${RED}[ERROR] Please install jq manually: https://stedolan.github.io/jq/${NC}"
        exit 1
    fi
fi
echo -e "${GREEN}[OK] jq installed${NC}"

# Verify AWS credentials
echo -e "\nVerifying AWS credentials..."
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "")
if [ -z "$AWS_ACCOUNT_ID" ]; then
    echo -e "${RED}[ERROR] AWS credentials not configured. Run: aws configure${NC}"
    exit 1
fi
echo -e "${GREEN}[OK] AWS Account ID: ${AWS_ACCOUNT_ID}${NC}"

################################################################################
# Step 2: Check Bedrock Model Access
################################################################################
echo -e "\n${YELLOW}[2/12] Checking Amazon Bedrock Access...${NC}"

check_bedrock_model() {
    local model_id=$1
    echo -e "Checking access to model: ${model_id}"
    
    if aws bedrock list-foundation-models --region $AWS_REGION \
        --query "modelSummaries[?modelId=='${model_id}'].modelId" \
        --output text 2>/dev/null | grep -q "${model_id}"; then
        echo -e "${GREEN}[OK] Model ${model_id} is accessible${NC}"
        return 0
    else
        echo -e "${RED}[ERROR] Model ${model_id} is NOT accessible${NC}"
        echo -e "${YELLOW}Action Required: Enable model access in AWS Console:${NC}"
        echo -e "   1. Go to: https://console.aws.amazon.com/bedrock/home?region=${AWS_REGION}#/modelaccess"
        echo -e "   2. Click 'Modify model access'"
        echo -e "   3. Enable: ${model_id}"
        echo -e "   4. Re-run this script"
        return 1
    fi
}

BEDROCK_OK=true
check_bedrock_model "$BEDROCK_MODEL_ID" || BEDROCK_OK=false
check_bedrock_model "$NOVA_MODEL_ID" || BEDROCK_OK=false

if [ "$BEDROCK_OK" = false ]; then
    read -p "Continue without Bedrock access? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

################################################################################
# Step 3: Create S3 Buckets
################################################################################
echo -e "\n${YELLOW}[3/12] Creating S3 Buckets...${NC}"

create_s3_bucket() {
    local bucket_name="$1"
    local purpose="$2"
    
    echo -e "Creating bucket: ${bucket_name} (${purpose})"
    
    if aws s3 ls "s3://${bucket_name}" 2>/dev/null; then
        echo -e "${YELLOW}[WARNING] Bucket already exists: ${bucket_name}${NC}"
    else
        if [ "$AWS_REGION" = "us-east-1" ]; then
            aws s3 mb "s3://${bucket_name}" --region $AWS_REGION
        else
            aws s3 mb "s3://${bucket_name}" --region $AWS_REGION --create-bucket-configuration LocationConstraint=$AWS_REGION
        fi
        
        # Enable versioning
        aws s3api put-bucket-versioning \
            --bucket "${bucket_name}" \
            --versioning-configuration Status=Enabled
        
        # Enable encryption
        aws s3api put-bucket-encryption \
            --bucket "${bucket_name}" \
            --server-side-encryption-configuration '{
                "Rules": [{
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256"
                    }
                }]
            }'
        
        # Block public access
        aws s3api put-public-access-block \
            --bucket "${bucket_name}" \
            --public-access-block-configuration \
                "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
        
        echo -e "${GREEN}[OK] Created bucket: ${bucket_name}${NC}"
    fi
}

# Create required buckets
ARTIFACTS_BUCKET="${PROJECT_NAME}-artifacts-${AWS_ACCOUNT_ID}"
DASHBOARD_BUCKET="${PROJECT_NAME}-dashboard-${AWS_ACCOUNT_ID}"
LOGS_BUCKET="${PROJECT_NAME}-logs-${AWS_ACCOUNT_ID}"
REPORTS_BUCKET="${PROJECT_NAME}-reports-${AWS_ACCOUNT_ID}"
TERRAFORM_STATE_BUCKET="${PROJECT_NAME}-terraform-state-${AWS_ACCOUNT_ID}"

create_s3_bucket "$ARTIFACTS_BUCKET" "Code, reports, artifacts"
create_s3_bucket "$DASHBOARD_BUCKET" "Dashboard static hosting"
create_s3_bucket "$LOGS_BUCKET" "Log archives"
create_s3_bucket "$REPORTS_BUCKET" "Compliance reports"
create_s3_bucket "$TERRAFORM_STATE_BUCKET" "Terraform state"

# Configure dashboard bucket for static website hosting
echo -e "Configuring dashboard bucket for static hosting..."
aws s3 website "s3://${DASHBOARD_BUCKET}" \
    --index-document index.html \
    --error-document error.html

################################################################################
# Step 4: Create DynamoDB Tables
################################################################################
echo -e "\n${YELLOW}[4/12] Creating DynamoDB Tables...${NC}"

create_dynamodb_table() {
    local table_name="$1"
    local key_schema="$2"
    local attribute_definitions="$3"
    local purpose="$4"
    local stream_enabled="${5:-false}"
    
    echo -e "Creating table: ${table_name} (${purpose})"
    
    if aws dynamodb describe-table --table-name "${table_name}" --region $AWS_REGION &>/dev/null; then
        echo -e "${YELLOW}[WARNING] Table already exists: ${table_name}${NC}"
    else
        local stream_spec=""
        if [ "$stream_enabled" = "true" ]; then
            stream_spec='--stream-specification StreamEnabled=true,StreamViewType=NEW_AND_OLD_IMAGES'
        fi
        
        aws dynamodb create-table \
            --table-name "${table_name}" \
            --key-schema ${key_schema} \
            --attribute-definitions ${attribute_definitions} \
            --billing-mode PAY_PER_REQUEST \
            --region $AWS_REGION \
            ${stream_spec} \
            --tags Key=Project,Value=${PROJECT_NAME} Key=Environment,Value=${ENVIRONMENT} \
            > /dev/null
        
        # Enable Point-in-Time Recovery
        aws dynamodb update-continuous-backups \
            --table-name "${table_name}" \
            --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true \
            --region $AWS_REGION \
            > /dev/null
        
        echo -e "${GREEN}[OK] Created table: ${table_name}${NC}"
    fi
}

# Violations table
create_dynamodb_table \
    "${PROJECT_NAME}-violations-${ENVIRONMENT}" \
    "AttributeName=violation_id,KeyType=HASH" \
    "AttributeName=violation_id,AttributeType=S" \
    "Violation records" \
    "false"

# Audit logs table (immutable)
create_dynamodb_table \
    "${PROJECT_NAME}-audit-logs-${ENVIRONMENT}" \
    "AttributeName=log_id,KeyType=HASH AttributeName=timestamp,KeyType=RANGE" \
    "AttributeName=log_id,AttributeType=S AttributeName=timestamp,AttributeType=N" \
    "Immutable audit trail" \
    "true"

# Agent memory table
create_dynamodb_table \
    "${PROJECT_NAME}-agent-memory-${ENVIRONMENT}" \
    "AttributeName=session_id,KeyType=HASH" \
    "AttributeName=session_id,AttributeType=S" \
    "Agent session memory" \
    "true"

# Compliance reports table
create_dynamodb_table \
    "${PROJECT_NAME}-reports-${ENVIRONMENT}" \
    "AttributeName=report_id,KeyType=HASH AttributeName=created_at,KeyType=RANGE" \
    "AttributeName=report_id,AttributeType=S AttributeName=created_at,AttributeType=N" \
    "Generated compliance reports" \
    "false"

# Scan results table
create_dynamodb_table \
    "${PROJECT_NAME}-scan-results-${ENVIRONMENT}" \
    "AttributeName=scan_id,KeyType=HASH" \
    "AttributeName=scan_id,AttributeType=S" \
    "Compliance scan results" \
    "false"

################################################################################
# Step 5: Create KMS Keys
################################################################################
echo -e "\n${YELLOW}[5/12] Creating KMS Encryption Keys...${NC}"

create_kms_key() {
    local key_description="$1"
    local key_alias="$2"
    
    echo -e "Creating KMS key: ${key_alias}"
    
    # Check if alias exists
    if aws kms describe-key --key-id "alias/${key_alias}" --region $AWS_REGION &>/dev/null; then
        echo -e "${YELLOW}[WARNING] KMS key already exists: ${key_alias}${NC}"
        KEY_ID=$(aws kms describe-key --key-id "alias/${key_alias}" --region $AWS_REGION --query 'KeyMetadata.KeyId' --output text)
    else
        # Create key
        KEY_ID=$(aws kms create-key \
            --description "${key_description}" \
            --key-usage ENCRYPT_DECRYPT \
            --origin AWS_KMS \
            --region $AWS_REGION \
            --tags TagKey=Project,TagValue=${PROJECT_NAME} TagKey=Environment,TagValue=${ENVIRONMENT} \
            --query 'KeyMetadata.KeyId' \
            --output text)
        
        # Create alias
        aws kms create-alias \
            --alias-name "alias/${key_alias}" \
            --target-key-id "${KEY_ID}" \
            --region $AWS_REGION
        
        # Enable key rotation
        aws kms enable-key-rotation \
            --key-id "${KEY_ID}" \
            --region $AWS_REGION
        
        echo -e "${GREEN}[OK] Created KMS key: ${key_alias} (${KEY_ID})${NC}"
    fi
}

create_kms_key "Compliance Guardian - Data Encryption" "${PROJECT_NAME}-data-key-${ENVIRONMENT}"
create_kms_key "Compliance Guardian - Secrets Encryption" "${PROJECT_NAME}-secrets-key-${ENVIRONMENT}"

################################################################################
# Step 6: Create IAM Roles for Agents
################################################################################
echo -e "\n${YELLOW}[6/12] Creating IAM Roles for 5 Agents...${NC}"

create_agent_role() {
    local agent_name="$1"
    local policy_document="$2"
    local role_name="${PROJECT_NAME}-${agent_name}-role-${ENVIRONMENT}"
    
    echo -e "Creating IAM role: ${role_name}"
    
    # Trust policy for Lambda
    local trust_policy='{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }'
    
    if aws iam get-role --role-name "${role_name}" &>/dev/null; then
        echo -e "${YELLOW}[WARNING] Role already exists: ${role_name}${NC}"
    else
        aws iam create-role \
            --role-name "${role_name}" \
            --assume-role-policy-document "${trust_policy}" \
            --tags Key=Project,Value=${PROJECT_NAME} Key=Environment,Value=${ENVIRONMENT} Key=Agent,Value=${agent_name} \
            > /dev/null
        
        # Attach basic Lambda execution policy
        aws iam attach-role-policy \
            --role-name "${role_name}" \
            --policy-arn "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
        
        # Create and attach custom policy
        local policy_name="${PROJECT_NAME}-${agent_name}-policy-${ENVIRONMENT}"
        aws iam create-policy \
            --policy-name "${policy_name}" \
            --policy-document "${policy_document}" \
            > /dev/null 2>&1 || true
        
        aws iam attach-role-policy \
            --role-name "${role_name}" \
            --policy-arn "arn:aws:iam::${AWS_ACCOUNT_ID}:policy/${policy_name}"
        
        echo -e "${GREEN}[OK] Created role: ${role_name}${NC}"
    fi
}

# Orchestrator Agent - Needs access to all resources
ORCHESTRATOR_POLICY='{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": ["dynamodb:*"],
            "Resource": "arn:aws:dynamodb:'$AWS_REGION':'$AWS_ACCOUNT_ID':table/'$PROJECT_NAME'-*"
        },
        {
            "Effect": "Allow",
            "Action": ["s3:*"],
            "Resource": ["arn:aws:s3:::'$PROJECT_NAME'-*", "arn:aws:s3:::'$PROJECT_NAME'-*/*"]
        },
        {
            "Effect": "Allow",
            "Action": ["lambda:InvokeFunction"],
            "Resource": "arn:aws:lambda:'$AWS_REGION':'$AWS_ACCOUNT_ID':function:'$PROJECT_NAME'-*"
        },
        {
            "Effect": "Allow",
            "Action": ["secretsmanager:GetSecretValue"],
            "Resource": "arn:aws:secretsmanager:'$AWS_REGION':'$AWS_ACCOUNT_ID':secret:'$PROJECT_NAME'-*"
        }
    ]
}'

# Compliance Agent - Read/write violations and scan results
COMPLIANCE_POLICY='{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["bedrock:InvokeModel"],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query", "dynamodb:Scan"],
            "Resource": [
                "arn:aws:dynamodb:'$AWS_REGION':'$AWS_ACCOUNT_ID':table/'$PROJECT_NAME'-violations-*",
                "arn:aws:dynamodb:'$AWS_REGION':'$AWS_ACCOUNT_ID':table/'$PROJECT_NAME'-scan-results-*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": "arn:aws:s3:::'$ARTIFACTS_BUCKET'/*"
        }
    ]
}'

# Remediation Agent - Needs Nova Act and code modification permissions
REMEDIATION_POLICY='{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["bedrock:InvokeModel"],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": ["dynamodb:GetItem", "dynamodb:UpdateItem"],
            "Resource": "arn:aws:dynamodb:'$AWS_REGION':'$AWS_ACCOUNT_ID':table/'$PROJECT_NAME'-violations-*"
        },
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": ["arn:aws:s3:::'$ARTIFACTS_BUCKET'/*", "arn:aws:s3:::'$REPORTS_BUCKET'/*"]
        },
        {
            "Effect": "Allow",
            "Action": ["secretsmanager:GetSecretValue"],
            "Resource": "arn:aws:secretsmanager:'$AWS_REGION':'$AWS_ACCOUNT_ID':secret:'$PROJECT_NAME'-*"
        }
    ]
}'

# Audit Agent - Write-only audit logs
AUDIT_POLICY='{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["bedrock:InvokeModel"],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": ["dynamodb:PutItem", "dynamodb:Query"],
            "Resource": "arn:aws:dynamodb:'$AWS_REGION':'$AWS_ACCOUNT_ID':table/'$PROJECT_NAME'-audit-logs-*"
        },
        {
            "Effect": "Allow",
            "Action": ["s3:PutObject"],
            "Resource": "arn:aws:s3:::'$REPORTS_BUCKET'/*"
        }
    ]
}'

# Risk Assessment Agent - Read violations, write assessments
RISK_POLICY='{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["bedrock:InvokeModel"],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query"],
            "Resource": [
                "arn:aws:dynamodb:'$AWS_REGION':'$AWS_ACCOUNT_ID':table/'$PROJECT_NAME'-violations-*",
                "arn:aws:dynamodb:'$AWS_REGION':'$AWS_ACCOUNT_ID':table/'$PROJECT_NAME'-scan-results-*"
            ]
        }
    ]
}'

create_agent_role "orchestrator" "$ORCHESTRATOR_POLICY"
create_agent_role "compliance" "$COMPLIANCE_POLICY"
create_agent_role "remediation" "$REMEDIATION_POLICY"
create_agent_role "audit" "$AUDIT_POLICY"
create_agent_role "risk-assessment" "$RISK_POLICY"

################################################################################
# Step 7: Create Secrets in Secrets Manager
################################################################################
echo -e "\n${YELLOW}[7/12] Initializing AWS Secrets Manager...${NC}"

create_secret() {
    local secret_name="$1"
    local secret_description="$2"
    local secret_value="$3"
    
    echo -e "Creating secret: ${secret_name}"
    
    if aws secretsmanager describe-secret --secret-id "${secret_name}" --region $AWS_REGION &>/dev/null; then
        echo -e "${YELLOW}[WARNING] Secret already exists: ${secret_name}${NC}"
    else
        aws secretsmanager create-secret \
            --name "${secret_name}" \
            --description "${secret_description}" \
            --secret-string "${secret_value}" \
            --region $AWS_REGION \
            --tags Key=Project,Value=${PROJECT_NAME} Key=Environment,Value=${ENVIRONMENT} \
            > /dev/null
        
        echo -e "${GREEN}[OK] Created secret: ${secret_name}${NC}"
        echo -e "${YELLOW}   → Update this secret with real values later!${NC}"
    fi
}

create_secret \
    "${PROJECT_NAME}/github/token" \
    "GitHub API token for repository access" \
    '{"token":"PLACEHOLDER_UPDATE_ME"}'

create_secret \
    "${PROJECT_NAME}/gitlab/token" \
    "GitLab API token for repository access" \
    '{"token":"PLACEHOLDER_UPDATE_ME"}'

create_secret \
    "${PROJECT_NAME}/slack/webhook" \
    "Slack webhook URL for notifications" \
    '{"webhook_url":"PLACEHOLDER_UPDATE_ME"}'

create_secret \
    "${PROJECT_NAME}/api/keys" \
    "API keys and JWT secret" \
    '{"jwt_secret":"'$(openssl rand -base64 32)'","api_key":"'$(openssl rand -hex 32)'"}'

################################################################################
# Step 8: Create CloudWatch Log Groups
################################################################################
echo -e "\n${YELLOW}[8/12] Creating CloudWatch Log Groups...${NC}"

create_log_group() {
    local log_group_name="$1"
    local retention_days="${2:-30}"
    
    echo -e "Creating log group: ${log_group_name}"
    
    if aws logs describe-log-groups --log-group-name-prefix "${log_group_name}" --region $AWS_REGION | grep -q "${log_group_name}"; then
        echo -e "${YELLOW}[WARNING] Log group already exists: ${log_group_name}${NC}"
    else
        aws logs create-log-group \
            --log-group-name "${log_group_name}" \
            --region $AWS_REGION
        
        aws logs put-retention-policy \
            --log-group-name "${log_group_name}" \
            --retention-in-days ${retention_days} \
            --region $AWS_REGION
        
        echo -e "${GREEN}[OK] Created log group: ${log_group_name} (${retention_days} days retention)${NC}"
    fi
}

create_log_group "/aws/lambda/${PROJECT_NAME}-orchestrator-${ENVIRONMENT}" 30
create_log_group "/aws/lambda/${PROJECT_NAME}-compliance-${ENVIRONMENT}" 30
create_log_group "/aws/lambda/${PROJECT_NAME}-remediation-${ENVIRONMENT}" 30
create_log_group "/aws/lambda/${PROJECT_NAME}-audit-${ENVIRONMENT}" 90
create_log_group "/aws/lambda/${PROJECT_NAME}-risk-assessment-${ENVIRONMENT}" 30
create_log_group "/aws/apigateway/${PROJECT_NAME}-${ENVIRONMENT}" 14

################################################################################
# Step 9: Create API Gateway
################################################################################
echo -e "\n${YELLOW}[9/12] Creating API Gateway...${NC}"

API_NAME="${PROJECT_NAME}-api-${ENVIRONMENT}"

# Check if API exists
API_ID=$(aws apigateway get-rest-apis --region $AWS_REGION --query "items[?name=='${API_NAME}'].id" --output text)

if [ -n "$API_ID" ]; then
    echo -e "${YELLOW}[WARNING] API Gateway already exists: ${API_NAME} (${API_ID})${NC}"
else
    API_ID=$(aws apigateway create-rest-api \
        --name "${API_NAME}" \
        --description "Compliance Guardian AI REST API" \
        --endpoint-configuration types=REGIONAL \
        --region $AWS_REGION \
        --query 'id' \
        --output text)
    
    echo -e "${GREEN}[OK] Created API Gateway: ${API_NAME} (${API_ID})${NC}"
fi

API_ENDPOINT="https://${API_ID}.execute-api.${AWS_REGION}.amazonaws.com/${ENVIRONMENT}"

################################################################################
# Step 10: Create VPC and Networking (Optional)
################################################################################
echo -e "\n${YELLOW}[10/12] Creating VPC and Networking...${NC}"

VPC_NAME="${PROJECT_NAME}-vpc-${ENVIRONMENT}"
VPC_CIDR="10.0.0.0/16"

# Check if VPC exists
VPC_ID=$(aws ec2 describe-vpcs --region $AWS_REGION --filters "Name=tag:Name,Values=${VPC_NAME}" --query 'Vpcs[0].VpcId' --output text 2>/dev/null || echo "")

if [ "$VPC_ID" != "None" ] && [ -n "$VPC_ID" ]; then
    echo -e "${YELLOW}[WARNING] VPC already exists: ${VPC_NAME} (${VPC_ID})${NC}"
else
    echo -e "Creating VPC: ${VPC_NAME}"
    
    VPC_ID=$(aws ec2 create-vpc \
        --cidr-block ${VPC_CIDR} \
        --region $AWS_REGION \
        --tag-specifications "ResourceType=vpc,Tags=[{Key=Name,Value=${VPC_NAME}},{Key=Project,Value=${PROJECT_NAME}}]" \
        --query 'Vpc.VpcId' \
        --output text)
    
    # Enable DNS hostnames
    aws ec2 modify-vpc-attribute --vpc-id ${VPC_ID} --enable-dns-hostnames
    
    # Create Internet Gateway
    IGW_ID=$(aws ec2 create-internet-gateway \
        --region $AWS_REGION \
        --tag-specifications "ResourceType=internet-gateway,Tags=[{Key=Name,Value=${VPC_NAME}-igw}]" \
        --query 'InternetGateway.InternetGatewayId' \
        --output text)
    
    aws ec2 attach-internet-gateway --vpc-id ${VPC_ID} --internet-gateway-id ${IGW_ID} --region $AWS_REGION
    
    # Create public subnets in 2 AZs
    SUBNET1_ID=$(aws ec2 create-subnet \
        --vpc-id ${VPC_ID} \
        --cidr-block 10.0.1.0/24 \
        --availability-zone ${AWS_REGION}a \
        --region $AWS_REGION \
        --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=${VPC_NAME}-public-1a}]" \
        --query 'Subnet.SubnetId' \
        --output text)
    
    SUBNET2_ID=$(aws ec2 create-subnet \
        --vpc-id ${VPC_ID} \
        --cidr-block 10.0.2.0/24 \
        --availability-zone ${AWS_REGION}b \
        --region $AWS_REGION \
        --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=${VPC_NAME}-public-1b}]" \
        --query 'Subnet.SubnetId' \
        --output text)
    
    # Create route table
    ROUTE_TABLE_ID=$(aws ec2 create-route-table \
        --vpc-id ${VPC_ID} \
        --region $AWS_REGION \
        --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=${VPC_NAME}-public-rt}]" \
        --query 'RouteTable.RouteTableId' \
        --output text)
    
    aws ec2 create-route --route-table-id ${ROUTE_TABLE_ID} --destination-cidr-block 0.0.0.0/0 --gateway-id ${IGW_ID} --region $AWS_REGION
    aws ec2 associate-route-table --subnet-id ${SUBNET1_ID} --route-table-id ${ROUTE_TABLE_ID} --region $AWS_REGION
    aws ec2 associate-route-table --subnet-id ${SUBNET2_ID} --route-table-id ${ROUTE_TABLE_ID} --region $AWS_REGION
    
    # Create security group
    SG_ID=$(aws ec2 create-security-group \
        --group-name "${VPC_NAME}-lambda-sg" \
        --description "Security group for Lambda functions" \
        --vpc-id ${VPC_ID} \
        --region $AWS_REGION \
        --query 'GroupId' \
        --output text)
    
    aws ec2 authorize-security-group-egress \
        --group-id ${SG_ID} \
        --ip-permissions IpProtocol=-1,IpRanges='[{CidrIp=0.0.0.0/0}]' \
        --region $AWS_REGION 2>/dev/null || true
    
    echo -e "${GREEN}[OK] Created VPC: ${VPC_NAME} (${VPC_ID})${NC}"
fi

################################################################################
# Step 11: Run Terraform
################################################################################
echo -e "\n${YELLOW}[11/12] Running Terraform Infrastructure Deployment...${NC}"

if [ ! -d "$TERRAFORM_DIR" ]; then
    echo -e "${RED}[ERROR] Terraform directory not found: ${TERRAFORM_DIR}${NC}"
else
    cd "$TERRAFORM_DIR"
    
    # Initialize Terraform with S3 backend
    echo -e "Initializing Terraform..."
    terraform init \
        -backend-config="bucket=${TERRAFORM_STATE_BUCKET}" \
        -backend-config="key=${ENVIRONMENT}/terraform.tfstate" \
        -backend-config="region=${AWS_REGION}"
    
    # Create terraform.tfvars
    cat > terraform.tfvars <<EOF
environment = "${ENVIRONMENT}"
aws_region = "${AWS_REGION}"
project_name = "${PROJECT_NAME}"
bedrock_model_id = "${BEDROCK_MODEL_ID}"
artifacts_bucket = "${ARTIFACTS_BUCKET}"
reports_bucket = "${REPORTS_BUCKET}"
EOF
    
    # Plan
    echo -e "Planning Terraform changes..."
    terraform plan -out=tfplan
    
    # Apply
    read -p "Apply Terraform changes? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        terraform apply tfplan
        echo -e "${GREEN}[OK] Terraform deployment complete${NC}"
    else
        echo -e "${YELLOW}[WARNING] Terraform apply skipped${NC}"
    fi
    
    cd - > /dev/null
fi

################################################################################
# Step 12: Output Summary
################################################################################
echo -e "\n${BLUE}================================================${NC}"
echo -e "${BLUE}  AWS Infrastructure Setup Complete!${NC}"
echo -e "${BLUE}================================================${NC}\n"

echo -e "${GREEN}[OK] AWS Account ID:${NC} ${AWS_ACCOUNT_ID}"
echo -e "${GREEN}[OK] Region:${NC} ${AWS_REGION}"
echo -e "${GREEN}[OK] Environment:${NC} ${ENVIRONMENT}\n"

echo -e "${YELLOW}S3 Buckets:${NC}"
echo -e "  • Artifacts: ${ARTIFACTS_BUCKET}"
echo -e "  • Dashboard: ${DASHBOARD_BUCKET}"
echo -e "  • Reports: ${REPORTS_BUCKET}"
echo -e "  • Logs: ${LOGS_BUCKET}"
echo -e "  • Terraform State: ${TERRAFORM_STATE_BUCKET}\n"

echo -e "${YELLOW}DynamoDB Tables:${NC}"
echo -e "  • Violations: ${PROJECT_NAME}-violations-${ENVIRONMENT}"
echo -e "  • Audit Logs: ${PROJECT_NAME}-audit-logs-${ENVIRONMENT}"
echo -e "  • Agent Memory: ${PROJECT_NAME}-agent-memory-${ENVIRONMENT}"
echo -e "  • Reports: ${PROJECT_NAME}-reports-${ENVIRONMENT}"
echo -e "  • Scan Results: ${PROJECT_NAME}-scan-results-${ENVIRONMENT}\n"

echo -e "${YELLOW}IAM Roles:${NC}"
echo -e "  • Orchestrator: ${PROJECT_NAME}-orchestrator-role-${ENVIRONMENT}"
echo -e "  • Compliance: ${PROJECT_NAME}-compliance-role-${ENVIRONMENT}"
echo -e "  • Remediation: ${PROJECT_NAME}-remediation-role-${ENVIRONMENT}"
echo -e "  • Audit: ${PROJECT_NAME}-audit-role-${ENVIRONMENT}"
echo -e "  • Risk Assessment: ${PROJECT_NAME}-risk-assessment-role-${ENVIRONMENT}\n"

echo -e "${YELLOW}API Gateway:${NC}"
echo -e "  • API ID: ${API_ID}"
echo -e "  • Endpoint: ${API_ENDPOINT}\n"

if [ -n "$VPC_ID" ] && [ "$VPC_ID" != "None" ]; then
    echo -e "${YELLOW}VPC:${NC}"
    echo -e "  • VPC ID: ${VPC_ID}"
    echo -e "  • CIDR: ${VPC_CIDR}\n"
fi

echo -e "${YELLOW}Dashboard URL:${NC}"
echo -e "  • http://${DASHBOARD_BUCKET}.s3-website-${AWS_REGION}.amazonaws.com\n"

echo -e "${YELLOW}Next Steps:${NC}"
echo -e "  1. Update Secrets Manager with real API tokens:"
echo -e "     aws secretsmanager update-secret --secret-id ${PROJECT_NAME}/github/token --secret-string '{\"token\":\"YOUR_TOKEN\"}'"
echo -e "  2. Deploy application code:"
echo -e "     ./scripts/deploy.sh ${ENVIRONMENT}"
echo -e "  3. Initialize agents:"
echo -e "     python scripts/init_agents.py"
echo -e "  4. Load compliance policies:"
echo -e "     python scripts/load_policies.py"
echo -e "  5. Generate test data:"
echo -e "     python scripts/generate_test_data.py"
echo -e "  6. Run demo:"
echo -e "     ./scripts/run_demo.sh\n"

echo -e "${GREEN}Setup complete! [CELEBRATE]${NC}\n"

# Save resource information to file
cat > "${PROJECT_NAME}-resources.txt" <<EOF
AWS_ACCOUNT_ID=${AWS_ACCOUNT_ID}
AWS_REGION=${AWS_REGION}
ENVIRONMENT=${ENVIRONMENT}
ARTIFACTS_BUCKET=${ARTIFACTS_BUCKET}
DASHBOARD_BUCKET=${DASHBOARD_BUCKET}
REPORTS_BUCKET=${REPORTS_BUCKET}
LOGS_BUCKET=${LOGS_BUCKET}
API_ID=${API_ID}
API_ENDPOINT=${API_ENDPOINT}
VPC_ID=${VPC_ID}
EOF

echo -e "${YELLOW}Resource information saved to: ${PROJECT_NAME}-resources.txt${NC}\n"
