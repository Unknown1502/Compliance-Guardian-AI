"""
Complete AWS Infrastructure Setup for Compliance Guardian AI
Creates IAM roles, DynamoDB tables, and S3 buckets
"""
import boto3
import json
import time
from botocore.exceptions import ClientError

# Configuration
REGION = "us-east-1"
ENVIRONMENT = "production"
PROJECT_NAME = "compliance-guardian-ai"
ACCOUNT_ID = "943598056704"

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    END = '\033[0m'

def print_status(message, color=Colors.BLUE):
    print(f"{color}{message}{Colors.END}")

def print_success(message):
    print(f"{Colors.GREEN}[OK] {message}{Colors.END}")

def print_error(message):
    print(f"{Colors.RED}[ERROR] {message}{Colors.END}")

def print_warning(message):
    print(f"{Colors.YELLOW}[WARNING]  {message}{Colors.END}")


def create_lambda_execution_role(role_name):
    """Create IAM role for Lambda with necessary permissions."""
    iam = boto3.client('iam', region_name=REGION)
    
    # Trust policy for Lambda
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }
        ]
    }
    
    try:
        # Create role
        response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description=f"Execution role for {PROJECT_NAME} Lambda functions"
        )
        
        print_success(f"Created IAM role: {role_name}")
        
        # Attach AWS managed policies
        managed_policies = [
            'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole',
            'arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess',
            'arn:aws:iam::aws:policy/AmazonS3FullAccess',
        ]
        
        for policy_arn in managed_policies:
            iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            print_success(f"  Attached policy: {policy_arn.split('/')[-1]}")
        
        # Create custom policy for Bedrock
        bedrock_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "bedrock:InvokeModel",
                        "bedrock:InvokeModelWithResponseStream"
                    ],
                    "Resource": "*"
                }
            ]
        }
        
        policy_name = f"{role_name}-bedrock-policy"
        try:
            iam.put_role_policy(
                RoleName=role_name,
                PolicyName=policy_name,
                PolicyDocument=json.dumps(bedrock_policy)
            )
            print_success(f"  Attached inline Bedrock policy")
        except ClientError as e:
            if e.response['Error']['Code'] != 'EntityAlreadyExists':
                raise
        
        # Wait for role to be available
        time.sleep(10)
        
        role_arn = response['Role']['Arn']
        return role_arn
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'EntityAlreadyExists':
            print_warning(f"Role {role_name} already exists, using existing role")
            response = iam.get_role(RoleName=role_name)
            return response['Role']['Arn']
        else:
            print_error(f"Failed to create role: {e}")
            raise


def create_dynamodb_table(table_name, key_schema, attribute_definitions):
    """Create DynamoDB table."""
    dynamodb = boto3.client('dynamodb', region_name=REGION)
    
    try:
        response = dynamodb.create_table(
            TableName=table_name,
            KeySchema=key_schema,
            AttributeDefinitions=attribute_definitions,
            BillingMode='PAY_PER_REQUEST',
            Tags=[
                {'Key': 'Environment', 'Value': ENVIRONMENT},
                {'Key': 'Project', 'Value': PROJECT_NAME}
            ]
        )
        
        print_success(f"Created DynamoDB table: {table_name}")
        
        # Wait for table to be active
        print_status(f"  Waiting for table to be active...")
        waiter = dynamodb.get_waiter('table_exists')
        waiter.wait(TableName=table_name)
        print_success(f"  Table {table_name} is now active")
        
        return response['TableDescription']['TableArn']
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceInUseException':
            print_warning(f"Table {table_name} already exists")
            response = dynamodb.describe_table(TableName=table_name)
            return response['Table']['TableArn']
        else:
            print_error(f"Failed to create table: {e}")
            raise


def create_s3_bucket(bucket_name):
    """Create S3 bucket."""
    s3 = boto3.client('s3', region_name=REGION)
    
    try:
        if REGION == 'us-east-1':
            s3.create_bucket(Bucket=bucket_name)
        else:
            s3.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': REGION}
            )
        
        print_success(f"Created S3 bucket: {bucket_name}")
        return f"arn:aws:s3:::{bucket_name}"
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'BucketAlreadyOwnedByYou':
            print_warning(f"Bucket {bucket_name} already exists")
            return f"arn:aws:s3:::{bucket_name}"
        else:
            print_error(f"Failed to create bucket: {e}")
            raise


def setup_infrastructure():
    """Set up all AWS infrastructure."""
    print_status("=" * 70)
    print_status("[BUILD]  COMPLIANCE GUARDIAN AI - INFRASTRUCTURE SETUP")
    print_status(f"   Environment: {ENVIRONMENT}")
    print_status(f"   Region: {REGION}")
    print_status("=" * 70)
    
    resources = {}
    
    # 1. Create IAM Role
    print_status("\n[1/4] Creating IAM Roles...")
    role_name = f"{PROJECT_NAME}-lambda-role-{ENVIRONMENT}"
    resources['lambda_role'] = create_lambda_execution_role(role_name)
    
    # 2. Create DynamoDB Tables
    print_status("\n[2/4] Creating DynamoDB Tables...")
    
    tables = {
        'violations': {
            'name': f'{PROJECT_NAME}-violations-{ENVIRONMENT}',
            'key_schema': [{'AttributeName': 'violation_id', 'KeyType': 'HASH'}],
            'attributes': [{'AttributeName': 'violation_id', 'AttributeType': 'S'}]
        },
        'audit_logs': {
            'name': f'{PROJECT_NAME}-audit-logs-{ENVIRONMENT}',
            'key_schema': [{'AttributeName': 'audit_id', 'KeyType': 'HASH'}],
            'attributes': [{'AttributeName': 'audit_id', 'AttributeType': 'S'}]
        },
        'agent_memory': {
            'name': f'{PROJECT_NAME}-agent-memory-{ENVIRONMENT}',
            'key_schema': [{'AttributeName': 'memory_id', 'KeyType': 'HASH'}],
            'attributes': [{'AttributeName': 'memory_id', 'AttributeType': 'S'}]
        },
        'reports': {
            'name': f'{PROJECT_NAME}-reports-{ENVIRONMENT}',
            'key_schema': [{'AttributeName': 'report_id', 'KeyType': 'HASH'}],
            'attributes': [{'AttributeName': 'report_id', 'AttributeType': 'S'}]
        },
        'scan_results': {
            'name': f'{PROJECT_NAME}-scan-results-{ENVIRONMENT}',
            'key_schema': [{'AttributeName': 'scan_id', 'KeyType': 'HASH'}],
            'attributes': [{'AttributeName': 'scan_id', 'AttributeType': 'S'}]
        }
    }
    
    for table_key, table_config in tables.items():
        resources[table_key] = create_dynamodb_table(
            table_config['name'],
            table_config['key_schema'],
            table_config['attributes']
        )
    
    # 3. Create S3 Buckets
    print_status("\n[3/4] Creating S3 Buckets...")
    
    buckets = [
        f'{PROJECT_NAME}-data-{ENVIRONMENT}',
        f'{PROJECT_NAME}-reports-{ENVIRONMENT}'
    ]
    
    for bucket_name in buckets:
        resources[bucket_name] = create_s3_bucket(bucket_name)
    
    # 4. Save configuration
    print_status("\n[4/4] Saving Infrastructure Configuration...")
    
    config = {
        'region': REGION,
        'environment': ENVIRONMENT,
        'account_id': ACCOUNT_ID,
        'lambda_role_arn': resources['lambda_role'],
        'tables': {
            'violations': tables['violations']['name'],
            'audit_logs': tables['audit_logs']['name'],
            'agent_memory': tables['agent_memory']['name'],
            'reports': tables['reports']['name'],
            'scan_results': tables['scan_results']['name']
        },
        'buckets': {
            'data': f'{PROJECT_NAME}-data-{ENVIRONMENT}',
            'reports': f'{PROJECT_NAME}-reports-{ENVIRONMENT}'
        }
    }
    
    with open('infrastructure_config.json', 'w') as f:
        json.dump(config, f, indent=2)
    
    print_success("Saved configuration to infrastructure_config.json")
    
    # Summary
    print_status("\n" + "=" * 70)
    print_status("[OK] [CELEBRATE] INFRASTRUCTURE SETUP COMPLETE!")
    print_status("=" * 70)
    
    print_status("\n[LIST] CREATED RESOURCES:")
    print_status(f"   [OK] IAM Role: {role_name}")
    print_status(f"   [OK] DynamoDB Tables: {len(tables)}")
    for table_key, table_config in tables.items():
        print_status(f"     - {table_config['name']}")
    print_status(f"   [OK] S3 Buckets: {len(buckets)}")
    for bucket in buckets:
        print_status(f"     - {bucket}")
    
    print_status("\n[NOTE] NEXT STEPS:")
    print_status("   1. Update Lambda functions with correct IAM role")
    print_status("   2. Run: python test_complete_workflow.py")
    
    return config


if __name__ == "__main__":
    try:
        setup_infrastructure()
    except Exception as e:
        print_error(f"Setup failed: {e}")
        import traceback
        traceback.print_exc()
