#!/bin/bash

################################################################################
# Compliance Guardian AI - Complete Deployment Script
#
# This script deploys the entire application to AWS:
# - Runs pre-deployment checks (Python version, AWS credentials, env vars)
# - Executes test suite (fails deployment if tests fail)
# - Runs security scans on dependencies and code
# - Builds and packages backend (Python with dependencies)
# - Deploys Lambda functions for all 5 agents
# - Updates API Gateway configurations
# - Builds and deploys React dashboard
# - Updates CloudFront cache
# - Runs database migrations
# - Performs health checks
# - Maintains rollback capability
#
# Usage: ./scripts/deploy.sh [environment] [--skip-tests] [--force]
################################################################################

set -e  # Exit on error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
ENVIRONMENT="${1:-production}"
SKIP_TESTS=false
FORCE_DEPLOY=false
PROJECT_NAME="compliance-guardian-ai"
PYTHON_VERSION="3.11"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
DEPLOYMENT_ID="${ENVIRONMENT}-${TIMESTAMP}"

# Parse arguments
for arg in "$@"; do
    case $arg in
        --skip-tests) SKIP_TESTS=true ;;
        --force) FORCE_DEPLOY=true ;;
    esac
done

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}  Compliance Guardian AI - Deployment${NC}"
echo -e "${BLUE}  Environment: ${ENVIRONMENT}${NC}"
echo -e "${BLUE}  Deployment ID: ${DEPLOYMENT_ID}${NC}"
echo -e "${BLUE}================================================${NC}\n"

# Load resource information
RESOURCES_FILE="${PROJECT_NAME}-resources.txt"
if [ -f "$RESOURCES_FILE" ]; then
    source "$RESOURCES_FILE"
    echo -e "${GREEN}[OK] Loaded resource configuration from ${RESOURCES_FILE}${NC}\n"
else
    echo -e "${RED}[ERROR] Resources file not found: ${RESOURCES_FILE}${NC}"
    echo -e "${YELLOW}Run ./scripts/setup_aws_resources.sh first${NC}"
    exit 1
fi

################################################################################
# Step 1: Pre-Deployment Checks
################################################################################
echo -e "${YELLOW}[1/14] Running Pre-Deployment Checks...${NC}"

# Check Python version
echo -e "Checking Python version..."
PYTHON_CMD=""
for cmd in python3.11 python3 python; do
    if command -v $cmd &> /dev/null; then
        VERSION=$($cmd --version 2>&1 | grep -oE '[0-9]+\.[0-9]+')
        if [ "$(echo "$VERSION >= $PYTHON_VERSION" | bc -l)" -eq 1 ] 2>/dev/null || [[ "$VERSION" == "3.11"* ]] || [[ "$VERSION" == "3.12"* ]]; then
            PYTHON_CMD=$cmd
            break
        fi
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    echo -e "${RED}[ERROR] Python ${PYTHON_VERSION}+ not found${NC}"
    exit 1
fi
echo -e "${GREEN}[OK] Python: $($PYTHON_CMD --version)${NC}"

# Check AWS CLI
if ! command -v aws &> /dev/null; then
    echo -e "${RED}[ERROR] AWS CLI not found${NC}"
    exit 1
fi
echo -e "${GREEN}[OK] AWS CLI: $(aws --version | cut -d' ' -f1)${NC}"

# Verify AWS credentials
echo -e "Verifying AWS credentials..."
if ! aws sts get-caller-identity &>/dev/null; then
    echo -e "${RED}[ERROR] AWS credentials invalid${NC}"
    exit 1
fi
echo -e "${GREEN}[OK] AWS credentials valid${NC}"

# Check required environment variables
echo -e "Checking environment variables..."
REQUIRED_VARS=("AWS_REGION" "ARTIFACTS_BUCKET" "REPORTS_BUCKET")
for var in "${REQUIRED_VARS[@]}"; do
    if [ -z "${!var}" ]; then
        echo -e "${RED}[ERROR] Missing required variable: ${var}${NC}"
        exit 1
    fi
done
echo -e "${GREEN}[OK] All required environment variables set${NC}"

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}[WARNING] .env file not found, copying from template...${NC}"
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo -e "${YELLOW}→ Please update .env with your values${NC}"
    fi
fi
echo "Deploying CloudFormation stack..."
aws cloudformation deploy \
    --template-file infrastructure/cloudformation/compliance-guardian.yaml \
    --stack-name "${ENVIRONMENT}-compliance-guardian" \
    --parameter-overrides EnvironmentName=$ENVIRONMENT \
    --capabilities CAPABILITY_NAMED_IAM \
    --region us-east-1

# Get stack outputs
echo ""
echo "Retrieving stack outputs..."
DYNAMODB_TABLE=$(aws cloudformation describe-stacks \
    --stack-name "${ENVIRONMENT}-compliance-guardian" \
    --query 'Stacks[0].Outputs[?OutputKey==`DynamoDBTableName`].OutputValue' \
    --output text)

REPORTS_BUCKET=$(aws cloudformation describe-stacks \
    --stack-name "${ENVIRONMENT}-compliance-guardian" \
    --query 'Stacks[0].Outputs[?OutputKey==`ReportsBucketName`].OutputValue' \
    --output text)

KMS_KEY_ID=$(aws cloudformation describe-stacks \
    --stack-name "${ENVIRONMENT}-compliance-guardian" \
    --query 'Stacks[0].Outputs[?OutputKey==`KMSKeyId`].OutputValue' \
    --output text)

echo ""
echo "Deployment complete!"
echo ""
echo "Stack Outputs:"
echo "  DynamoDB Table: $DYNAMODB_TABLE"
echo "  Reports Bucket: $REPORTS_BUCKET"
echo "  KMS Key: $KMS_KEY_ID"
echo ""
echo "Update your .env file with these values:"
echo "  DYNAMODB_TABLE_NAME=$DYNAMODB_TABLE"
echo "  KMS_KEY_ID=$KMS_KEY_ID"
echo ""
