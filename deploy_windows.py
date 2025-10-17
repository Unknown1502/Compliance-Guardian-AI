"""
Windows-compatible AWS Infrastructure Deployment Script
Deploys all AWS resources using boto3 (no bash/terraform needed)
"""
import boto3
import json
import time
from botocore.exceptions import ClientError

# Configuration
REGION = "us-east-1"
ENVIRONMENT = "production"
PROJECT_NAME = "compliance-guardian-ai"

# Color output for Windows terminal
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    END = '\033[0m'

def print_status(message, color=Colors.BLUE):
    """Print colored status message."""
    print(f"{color}{message}{Colors.END}")

def print_success(message):
    """Print success message."""
    print(f"{Colors.GREEN}[OK] {message}{Colors.END}")

def print_error(message):
    """Print error message."""
    print(f"{Colors.RED}[ERROR] {message}{Colors.END}")

def print_warning(message):
    """Print warning message."""
    print(f"{Colors.YELLOW}[WARNING]  {message}{Colors.END}")


def create_s3_buckets():
    """Create S3 buckets for data, artifacts, and logs."""
    print_status("\n[Step 1/8] Creating S3 Buckets...")
    
    s3 = boto3.client('s3', region_name=REGION)
    
    buckets = [
        f"{PROJECT_NAME}-data-{ENVIRONMENT}",
        f"{PROJECT_NAME}-artifacts-{ENVIRONMENT}",
        f"{PROJECT_NAME}-logs-{ENVIRONMENT}",
        f"{PROJECT_NAME}-reports-{ENVIRONMENT}",
        f"{PROJECT_NAME}-dashboard-{ENVIRONMENT}",
    ]
    
    for bucket_name in buckets:
        try:
            # Create bucket
            if REGION == 'us-east-1':
                s3.create_bucket(Bucket=bucket_name)
            else:
                s3.create_bucket(
                    Bucket=bucket_name,
                    CreateBucketConfiguration={'LocationConstraint': REGION}
                )
            
            # Enable versioning
            s3.put_bucket_versioning(
                Bucket=bucket_name,
                VersioningConfiguration={'Status': 'Enabled'}
            )
            
            # Enable encryption
            s3.put_bucket_encryption(
                Bucket=bucket_name,
                ServerSideEncryptionConfiguration={
                    'Rules': [{
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        }
                    }]
                }
            )
            
            # Block public access
            s3.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            
            print_success(f"Created S3 bucket: {bucket_name}")
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'BucketAlreadyOwnedByYou':
                print_warning(f"Bucket already exists: {bucket_name}")
            else:
                print_error(f"Failed to create bucket {bucket_name}: {e}")
                raise


def create_dynamodb_tables():
    """Create DynamoDB tables for violations, audit logs, etc."""
    print_status("\n[Step 2/8] Creating DynamoDB Tables...")
    
    dynamodb = boto3.client('dynamodb', region_name=REGION)
    
    tables = [
        {
            'name': f"{PROJECT_NAME}-violations-{ENVIRONMENT}",
            'hash_key': 'violation_id',
            'range_key': 'timestamp',
        },
        {
            'name': f"{PROJECT_NAME}-audit-logs-{ENVIRONMENT}",
            'hash_key': 'log_id',
            'range_key': 'timestamp',
        },
        {
            'name': f"{PROJECT_NAME}-agent-memory-{ENVIRONMENT}",
            'hash_key': 'agent_id',
            'range_key': 'conversation_id',
        },
        {
            'name': f"{PROJECT_NAME}-reports-{ENVIRONMENT}",
            'hash_key': 'report_id',
            'range_key': 'created_at',
        },
        {
            'name': f"{PROJECT_NAME}-scan-results-{ENVIRONMENT}",
            'hash_key': 'scan_id',
            'range_key': 'timestamp',
        },
    ]
    
    for table_config in tables:
        try:
            table_name = table_config['name']
            
            dynamodb.create_table(
                TableName=table_name,
                KeySchema=[
                    {'AttributeName': table_config['hash_key'], 'KeyType': 'HASH'},
                    {'AttributeName': table_config['range_key'], 'KeyType': 'RANGE'}
                ],
                AttributeDefinitions=[
                    {'AttributeName': table_config['hash_key'], 'AttributeType': 'S'},
                    {'AttributeName': table_config['range_key'], 'AttributeType': 'S'}
                ],
                BillingMode='PAY_PER_REQUEST',  # On-demand pricing
                SSESpecification={
                    'Enabled': True,
                    'SSEType': 'KMS'
                },
                Tags=[
                    {'Key': 'Environment', 'Value': ENVIRONMENT},
                    {'Key': 'Project', 'Value': PROJECT_NAME}
                ]
            )
            
            print_success(f"Created DynamoDB table: {table_name}")
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceInUseException':
                print_warning(f"Table already exists: {table_name}")
            else:
                print_error(f"Failed to create table {table_name}: {e}")
                raise
    
    # Wait for tables to become active
    print_status("Waiting for tables to become active...")
    time.sleep(5)


def create_iam_roles():
    """Create IAM roles for Lambda functions."""
    print_status("\n[Step 3/8] Creating IAM Roles...")
    
    iam = boto3.client('iam', region_name=REGION)
    
    # Trust policy for Lambda
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }
    
    roles = [
        'orchestrator-agent',
        'compliance-agent',
        'audit-agent',
        'remediation-agent',
        'explainability-agent',
        'api-handler'
    ]
    
    for role_name in roles:
        full_role_name = f"{PROJECT_NAME}-{role_name}-{ENVIRONMENT}"
        
        try:
            role = iam.create_role(
                RoleName=full_role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Description=f"Role for {role_name} in Compliance Guardian AI",
                Tags=[
                    {'Key': 'Environment', 'Value': ENVIRONMENT},
                    {'Key': 'Project', 'Value': PROJECT_NAME}
                ]
            )
            
            # Attach basic Lambda execution policy
            iam.attach_role_policy(
                RoleName=full_role_name,
                PolicyArn='arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
            )
            
            # Create and attach custom policy for Bedrock, DynamoDB, S3
            custom_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "bedrock:InvokeModel",
                            "bedrock:InvokeModelWithResponseStream"
                        ],
                        "Resource": "*"
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "dynamodb:GetItem",
                            "dynamodb:PutItem",
                            "dynamodb:UpdateItem",
                            "dynamodb:Query",
                            "dynamodb:Scan"
                        ],
                        "Resource": f"arn:aws:dynamodb:{REGION}:*:table/{PROJECT_NAME}-*"
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:GetObject",
                            "s3:PutObject",
                            "s3:ListBucket"
                        ],
                        "Resource": [
                            f"arn:aws:s3:::{PROJECT_NAME}-*",
                            f"arn:aws:s3:::{PROJECT_NAME}-*/*"
                        ]
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "kms:Decrypt",
                            "kms:Encrypt",
                            "kms:GenerateDataKey"
                        ],
                        "Resource": "*"
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents"
                        ],
                        "Resource": "*"
                    }
                ]
            }
            
            policy_name = f"{full_role_name}-policy"
            iam.put_role_policy(
                RoleName=full_role_name,
                PolicyName=policy_name,
                PolicyDocument=json.dumps(custom_policy)
            )
            
            print_success(f"Created IAM role: {full_role_name}")
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'EntityAlreadyExists':
                print_warning(f"Role already exists: {full_role_name}")
            else:
                print_error(f"Failed to create role {full_role_name}: {e}")
                raise


def create_cloudwatch_log_groups():
    """Create CloudWatch log groups."""
    print_status("\n[Step 4/8] Creating CloudWatch Log Groups...")
    
    logs = boto3.client('logs', region_name=REGION)
    
    log_groups = [
        f"/aws/lambda/{PROJECT_NAME}-orchestrator-{ENVIRONMENT}",
        f"/aws/lambda/{PROJECT_NAME}-compliance-{ENVIRONMENT}",
        f"/aws/lambda/{PROJECT_NAME}-audit-{ENVIRONMENT}",
        f"/aws/lambda/{PROJECT_NAME}-remediation-{ENVIRONMENT}",
        f"/aws/lambda/{PROJECT_NAME}-explainability-{ENVIRONMENT}",
        f"/aws/lambda/{PROJECT_NAME}-api-{ENVIRONMENT}",
        f"/aws/compliance-guardian/{ENVIRONMENT}/application",
    ]
    
    for log_group_name in log_groups:
        try:
            logs.create_log_group(logGroupName=log_group_name)
            
            # Set retention to 30 days
            logs.put_retention_policy(
                logGroupName=log_group_name,
                retentionInDays=30
            )
            
            print_success(f"Created log group: {log_group_name}")
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceAlreadyExistsException':
                print_warning(f"Log group already exists: {log_group_name}")
            else:
                print_error(f"Failed to create log group {log_group_name}: {e}")


def create_sqs_queues():
    """Create SQS queues for async processing."""
    print_status("\n[Step 5/8] Creating SQS Queues...")
    
    sqs = boto3.client('sqs', region_name=REGION)
    
    queues = [
        f"{PROJECT_NAME}-scan-queue-{ENVIRONMENT}",
        f"{PROJECT_NAME}-remediation-queue-{ENVIRONMENT}",
        f"{PROJECT_NAME}-notifications-queue-{ENVIRONMENT}",
    ]
    
    created_queues = {}
    
    for queue_name in queues:
        try:
            response = sqs.create_queue(
                QueueName=queue_name,
                Attributes={
                    'DelaySeconds': '0',
                    'MessageRetentionPeriod': '345600',  # 4 days
                    'VisibilityTimeout': '300',  # 5 minutes
                    'ReceiveMessageWaitTimeSeconds': '20',  # Long polling
                }
            )
            
            created_queues[queue_name] = response['QueueUrl']
            print_success(f"Created SQS queue: {queue_name}")
            
        except ClientError as e:
            if 'QueueAlreadyExists' in str(e):
                print_warning(f"Queue already exists: {queue_name}")
            else:
                print_error(f"Failed to create queue {queue_name}: {e}")
    
    return created_queues


def create_sns_topics():
    """Create SNS topics for notifications."""
    print_status("\n[Step 6/8] Creating SNS Topics...")
    
    sns = boto3.client('sns', region_name=REGION)
    
    topics = [
        f"{PROJECT_NAME}-violations-{ENVIRONMENT}",
        f"{PROJECT_NAME}-remediation-{ENVIRONMENT}",
        f"{PROJECT_NAME}-alerts-{ENVIRONMENT}",
    ]
    
    created_topics = {}
    
    for topic_name in topics:
        try:
            response = sns.create_topic(
                Name=topic_name,
                Attributes={
                    'DisplayName': topic_name,
                },
                Tags=[
                    {'Key': 'Environment', 'Value': ENVIRONMENT},
                    {'Key': 'Project', 'Value': PROJECT_NAME}
                ]
            )
            
            created_topics[topic_name] = response['TopicArn']
            print_success(f"Created SNS topic: {topic_name}")
            
        except ClientError as e:
            print_error(f"Failed to create topic {topic_name}: {e}")
    
    return created_topics


def verify_bedrock_access():
    """Verify Bedrock model access."""
    print_status("\n[Step 7/8] Verifying Bedrock Access...")
    
    bedrock_runtime = boto3.client('bedrock-runtime', region_name=REGION)
    
    model_id = "us.anthropic.claude-3-5-sonnet-20241022-v2:0"
    
    try:
        response = bedrock_runtime.invoke_model(
            modelId=model_id,
            body=json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 10,
                "messages": [{"role": "user", "content": "Test"}]
            })
        )
        
        print_success(f"[OK] Bedrock access verified for {model_id}")
        return True
        
    except ClientError as e:
        print_error(f"Bedrock access failed: {e}")
        return False


def save_deployment_config(queues, topics):
    """Save deployment configuration to .env file."""
    print_status("\n[Step 8/8] Saving Deployment Configuration...")
    
    sts = boto3.client('sts')
    identity = sts.get_caller_identity()
    account_id = identity['Account']
    
    config_content = f"""# Auto-generated deployment configuration
# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}

# AWS Configuration
AWS_REGION={REGION}
AWS_ACCOUNT_ID={account_id}
ENVIRONMENT={ENVIRONMENT}

# Bedrock
BEDROCK_MODEL_ID=us.anthropic.claude-3-5-sonnet-20241022-v2:0
BEDROCK_REGION={REGION}

# S3 Buckets
S3_DATA_BUCKET={PROJECT_NAME}-data-{ENVIRONMENT}
S3_ARTIFACTS_BUCKET={PROJECT_NAME}-artifacts-{ENVIRONMENT}
S3_LOGS_BUCKET={PROJECT_NAME}-logs-{ENVIRONMENT}
S3_REPORTS_BUCKET={PROJECT_NAME}-reports-{ENVIRONMENT}
S3_DASHBOARD_BUCKET={PROJECT_NAME}-dashboard-{ENVIRONMENT}

# DynamoDB Tables
DYNAMODB_VIOLATIONS_TABLE={PROJECT_NAME}-violations-{ENVIRONMENT}
DYNAMODB_AUDIT_TABLE={PROJECT_NAME}-audit-logs-{ENVIRONMENT}
DYNAMODB_MEMORY_TABLE={PROJECT_NAME}-agent-memory-{ENVIRONMENT}
DYNAMODB_REPORTS_TABLE={PROJECT_NAME}-reports-{ENVIRONMENT}
DYNAMODB_SCANS_TABLE={PROJECT_NAME}-scan-results-{ENVIRONMENT}

# SQS Queues (add URLs manually or from deployment output)
# SQS_SCAN_QUEUE_URL=
# SQS_REMEDIATION_QUEUE_URL=

# SNS Topics (add ARNs manually or from deployment output)
# SNS_VIOLATIONS_TOPIC=
# SNS_REMEDIATION_TOPIC=

# Application
LOG_LEVEL=INFO
DEBUG=false
"""
    
    with open('.env.deployment', 'w') as f:
        f.write(config_content)
    
    print_success("Saved configuration to .env.deployment")
    print_warning("\n[WARNING]  IMPORTANT: Copy .env.deployment values to your .env file!")


def main():
    """Main deployment function."""
    print_status("=" * 60)
    print_status(f"[LAUNCH] COMPLIANCE GUARDIAN AI - AWS INFRASTRUCTURE DEPLOYMENT")
    print_status(f"   Environment: {ENVIRONMENT}")
    print_status(f"   Region: {REGION}")
    print_status("=" * 60)
    
    try:
        # Step 1: Create S3 buckets
        create_s3_buckets()
        
        # Step 2: Create DynamoDB tables
        create_dynamodb_tables()
        
        # Step 3: Create IAM roles
        create_iam_roles()
        
        # Step 4: Create CloudWatch log groups
        create_cloudwatch_log_groups()
        
        # Step 5: Create SQS queues
        queues = create_sqs_queues()
        
        # Step 6: Create SNS topics
        topics = create_sns_topics()
        
        # Step 7: Verify Bedrock access
        verify_bedrock_access()
        
        # Step 8: Save deployment configuration
        save_deployment_config(queues, topics)
        
        print_status("\n" + "=" * 60)
        print_success("[CELEBRATE] INFRASTRUCTURE DEPLOYMENT COMPLETE!")
        print_status("=" * 60)
        
        print_status("\n[LIST] NEXT STEPS:")
        print_status("   1. Review .env.deployment file")
        print_status("   2. Update your .env file with the new values")
        print_status("   3. Run: python deploy_lambda.py (to deploy Lambda functions)")
        print_status("\n[MONEY] ESTIMATED MONTHLY COST: $15-25 (with $100 credits = 4-6 months free)")
        
    except Exception as e:
        print_error(f"\n[BOOM] Deployment failed: {e}")
        print_error("Check error messages above and retry.")
        raise


if __name__ == "__main__":
    main()
