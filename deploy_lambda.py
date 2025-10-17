"""
Windows-compatible Lambda Deployment Script
Packages and deploys all 6 Lambda functions for Compliance Guardian AI
Uses S3 for large packages to avoid SSL/timeout issues
"""
import boto3
import json
import os
import shutil
import zipfile
import time
from pathlib import Path
from botocore.exceptions import ClientError, SSLError
from botocore.config import Config
from functools import wraps

# Configuration
REGION = "us-east-1"
ENVIRONMENT = "production"
PROJECT_NAME = "compliance-guardian-ai"
ACCOUNT_ID = "943598056704"
DEPLOYMENT_BUCKET = f"{PROJECT_NAME}-deployment-{ENVIRONMENT}"

# Boto3 configuration to handle large files and SSL issues
boto_config = Config(
    region_name=REGION,
    retries={'max_attempts': 10, 'mode': 'adaptive'},
    max_pool_connections=50,
    connect_timeout=300,
    read_timeout=300
)

# Color output
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


def ensure_s3_bucket():
    """Ensure S3 deployment bucket exists."""
    s3_client = boto3.client('s3', config=boto_config)
    
    try:
        s3_client.head_bucket(Bucket=DEPLOYMENT_BUCKET)
        print_status(f"[OK] Using existing S3 bucket: {DEPLOYMENT_BUCKET}")
    except ClientError:
        print_status(f"[PACKAGE] Creating S3 bucket: {DEPLOYMENT_BUCKET}")
        try:
            if REGION == 'us-east-1':
                s3_client.create_bucket(Bucket=DEPLOYMENT_BUCKET)
            else:
                s3_client.create_bucket(
                    Bucket=DEPLOYMENT_BUCKET,
                    CreateBucketConfiguration={'LocationConstraint': REGION}
                )
            print_success(f"Created S3 bucket: {DEPLOYMENT_BUCKET}")
        except ClientError as e:
            print_error(f"Failed to create S3 bucket: {e}")
            raise


def upload_to_s3(file_path, s3_key):
    """Upload file to S3 using multipart upload for reliability."""
    s3_client = boto3.client('s3', config=boto_config)
    
    file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
    print_status(f"[UPLOAD] Uploading to S3: {s3_key} ({file_size_mb:.1f} MB)")
    
    try:
        # Use multipart upload for files > 100MB
        if file_size_mb > 100:
            from boto3.s3.transfer import TransferConfig
            print_status(f"   Using multipart upload (large file)...")
            # Upload with progress
            transfer_config = TransferConfig(
                multipart_threshold=1024 * 1024 * 100,  # 100MB
                max_concurrency=10,
                multipart_chunksize=1024 * 1024 * 100,  # 100MB
                use_threads=True
            )
            s3_client.upload_file(file_path, DEPLOYMENT_BUCKET, s3_key, Config=transfer_config)
        else:
            s3_client.upload_file(file_path, DEPLOYMENT_BUCKET, s3_key)
        
        print_success(f"Uploaded to s3://{DEPLOYMENT_BUCKET}/{s3_key}")
        return f"s3://{DEPLOYMENT_BUCKET}/{s3_key}"
        
    except Exception as e:
        print_error(f"Failed to upload to S3: {e}")
        raise


def retry_on_ssl_error(max_retries=3, delay=2):
    """Decorator to retry on SSL errors with exponential backoff."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except SSLError as e:
                    if attempt < max_retries - 1:
                        wait_time = delay * (2 ** attempt)
                        print_warning(f"SSL error occurred (attempt {attempt + 1}/{max_retries}). Retrying in {wait_time}s...")
                        time.sleep(wait_time)
                    else:
                        print_error(f"SSL error persisted after {max_retries} attempts")
                        raise
                except Exception as e:
                    # Don't retry on other exceptions
                    raise
            return None
        return wrapper
    return decorator


def create_deployment_package(function_name, handler_file, include_all_src=True):
    """Create a deployment ZIP package for Lambda."""
    print_status(f"\n[PACKAGE] Packaging {function_name}...")
    
    # Create temp directory
    package_dir = Path(f"temp_package_{function_name}")
    package_dir.mkdir(exist_ok=True)
    
    try:
        # Copy source code
        if include_all_src:
            # Copy entire src directory
            src_dest = package_dir / "src"
            if src_dest.exists():
                shutil.rmtree(src_dest)
            shutil.copytree("src", src_dest, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
            print_status(f"   Copied src/ directory")
        
        # Copy requirements (we'll install dependencies)
        # Note: For production, you'd use Lambda Layers, but for hackathon speed we'll bundle
        
        # Install dependencies into package (use Lambda-optimized requirements)
        print_status(f"   Installing dependencies...")
        requirements_file = 'requirements-lambda.txt' if os.path.exists('requirements-lambda.txt') else 'requirements.txt'
        print_status(f"   Using: {requirements_file}")
        os.system(f'pip install -r {requirements_file} -t "{package_dir}" --quiet --upgrade --no-cache-dir')
        
        # Create ZIP file
        zip_path = f"{function_name}.zip"
        print_status(f"   Creating ZIP: {zip_path}")
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(package_dir):
                # Skip __pycache__ and .pyc files
                dirs[:] = [d for d in dirs if d != '__pycache__']
                
                for file in files:
                    if file.endswith('.pyc'):
                        continue
                    
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, package_dir)
                    zipf.write(file_path, arcname)
        
        # Get ZIP size
        zip_size_mb = os.path.getsize(zip_path) / (1024 * 1024)
        print_success(f"Package created: {zip_path} ({zip_size_mb:.1f} MB)")
        
        return zip_path
        
    finally:
        # Cleanup temp directory
        if package_dir.exists():
            shutil.rmtree(package_dir)


def create_lambda_function(function_name, handler, role_arn, zip_path, description, timeout=300, memory=512):
    """Create or update a Lambda function using S3 for large packages."""
    print_status(f"\n[LAUNCH] Deploying Lambda: {function_name}")
    
    lambda_client = boto3.client('lambda', config=boto_config)
    
    # Get file size to determine deployment method
    zip_size_mb = os.path.getsize(zip_path) / (1024 * 1024)
    
    # For large files (>50MB), use S3; for small files, direct upload
    use_s3 = zip_size_mb > 50
    
    if use_s3:
        # Upload to S3 first
        s3_key = f"lambda-deployments/{function_name}/{os.path.basename(zip_path)}"
        s3_url = upload_to_s3(zip_path, s3_key)
        code_location = {
            'S3Bucket': DEPLOYMENT_BUCKET,
            'S3Key': s3_key
        }
    else:
        # Direct upload for small files
        with open(zip_path, 'rb') as f:
            zip_content = f.read()
        code_location = {'ZipFile': zip_content}
    
    # Environment variables (AWS_REGION is reserved and auto-set by Lambda)
    env_vars = {
        'ENVIRONMENT': ENVIRONMENT,
        'BEDROCK_MODEL_ID': 'us.anthropic.claude-3-5-sonnet-20241022-v2:0',
        'DYNAMODB_VIOLATIONS_TABLE': f'{PROJECT_NAME}-violations-{ENVIRONMENT}',
        'DYNAMODB_AUDIT_TABLE': f'{PROJECT_NAME}-audit-logs-{ENVIRONMENT}',
        'DYNAMODB_MEMORY_TABLE': f'{PROJECT_NAME}-agent-memory-{ENVIRONMENT}',
        'DYNAMODB_REPORTS_TABLE': f'{PROJECT_NAME}-reports-{ENVIRONMENT}',
        'DYNAMODB_SCANS_TABLE': f'{PROJECT_NAME}-scan-results-{ENVIRONMENT}',
        'S3_DATA_BUCKET': f'{PROJECT_NAME}-data-{ENVIRONMENT}',
        'S3_REPORTS_BUCKET': f'{PROJECT_NAME}-reports-{ENVIRONMENT}',
        'LOG_LEVEL': 'INFO',
    }
    
    @retry_on_ssl_error(max_retries=3, delay=2)
    def update_function_code_with_retry():
        if use_s3:
            return lambda_client.update_function_code(
                FunctionName=function_name,
                S3Bucket=DEPLOYMENT_BUCKET,
                S3Key=s3_key
            )
        else:
            return lambda_client.update_function_code(
                FunctionName=function_name,
                ZipFile=zip_content
            )
    
    @retry_on_ssl_error(max_retries=3, delay=2)
    def update_function_config_with_retry():
        return lambda_client.update_function_configuration(
            FunctionName=function_name,
            Runtime='python3.11',
            Handler=handler,
            Timeout=timeout,
            MemorySize=memory,
            Environment={'Variables': env_vars}
        )
    
    @retry_on_ssl_error(max_retries=3, delay=2)
    def create_function_with_retry():
        return lambda_client.create_function(
            FunctionName=function_name,
            Runtime='python3.11',
            Role=role_arn,
            Handler=handler,
            Code=code_location,
            Description=description,
            Timeout=timeout,
            MemorySize=memory,
            Environment={'Variables': env_vars},
            Tags={
                'Environment': ENVIRONMENT,
                'Project': PROJECT_NAME
            }
        )
    
    try:
        # Try to update existing function
        update_function_code_with_retry()
        
        # Update configuration
        update_function_config_with_retry()
        
        print_success(f"Updated existing function: {function_name}")
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            # Create new function
            response = create_function_with_retry()
            
            print_success(f"Created new function: {function_name}")
            print_status(f"   ARN: {response['FunctionArn']}")
        else:
            print_error(f"Failed to deploy {function_name}: {e}")
            raise
    
    # Wait for function to be ready
    time.sleep(2)
    
    return function_name


def create_api_gateway():
    """Create API Gateway REST API."""
    print_status("\n[WEB] Creating API Gateway...")
    
    api_client = boto3.client('apigateway', region_name=REGION)
    lambda_client = boto3.client('lambda', region_name=REGION)
    
    api_name = f"{PROJECT_NAME}-api-{ENVIRONMENT}"
    
    try:
        # Check if API exists
        apis = api_client.get_rest_apis()
        existing_api = None
        for api in apis['items']:
            if api['name'] == api_name:
                existing_api = api
                break
        
        if existing_api:
            api_id = existing_api['id']
            print_warning(f"Using existing API: {api_id}")
        else:
            # Create new API
            response = api_client.create_rest_api(
                name=api_name,
                description='Compliance Guardian AI REST API',
                endpointConfiguration={'types': ['REGIONAL']}
            )
            api_id = response['id']
            print_success(f"Created API Gateway: {api_id}")
        
        # Get root resource
        resources = api_client.get_resources(restApiId=api_id)
        root_id = resources['items'][0]['id']
        
        # Create /scan resource
        try:
            scan_resource = api_client.create_resource(
                restApiId=api_id,
                parentId=root_id,
                pathPart='scan'
            )
            scan_resource_id = scan_resource['id']
        except ClientError as e:
            if 'ConflictException' in str(e):
                # Resource exists, get it
                for resource in resources['items']:
                    if resource.get('pathPart') == 'scan':
                        scan_resource_id = resource['id']
                        break
                print_warning("Using existing /scan resource")
            else:
                raise
        
        # Create POST method on /scan
        try:
            api_client.put_method(
                restApiId=api_id,
                resourceId=scan_resource_id,
                httpMethod='POST',
                authorizationType='NONE'
            )
        except ClientError as e:
            if 'ConflictException' not in str(e):
                raise
        
        # Integrate with Lambda
        lambda_arn = f"arn:aws:lambda:{REGION}:{ACCOUNT_ID}:function:{PROJECT_NAME}-api-{ENVIRONMENT}"
        
        api_client.put_integration(
            restApiId=api_id,
            resourceId=scan_resource_id,
            httpMethod='POST',
            type='AWS_PROXY',
            integrationHttpMethod='POST',
            uri=f"arn:aws:apigateway:{REGION}:lambda:path/2015-03-31/functions/{lambda_arn}/invocations"
        )
        
        # Grant API Gateway permission to invoke Lambda
        try:
            lambda_client.add_permission(
                FunctionName=f"{PROJECT_NAME}-api-{ENVIRONMENT}",
                StatementId=f'apigateway-{api_id}',
                Action='lambda:InvokeFunction',
                Principal='apigateway.amazonaws.com',
                SourceArn=f"arn:aws:execute-api:{REGION}:{ACCOUNT_ID}:{api_id}/*/*"
            )
        except ClientError as e:
            if 'ResourceConflictException' not in str(e):
                raise
        
        # Deploy API
        try:
            deployment = api_client.create_deployment(
                restApiId=api_id,
                stageName=ENVIRONMENT
            )
            print_success(f"Deployed API to stage: {ENVIRONMENT}")
        except Exception as e:
            print_warning(f"Deployment note: {e}")
        
        # Get API URL
        api_url = f"https://{api_id}.execute-api.{REGION}.amazonaws.com/{ENVIRONMENT}"
        
        print_success(f"\n[CELEBRATE] API Gateway URL: {api_url}")
        print_status(f"   Endpoint: {api_url}/scan")
        
        return api_url
        
    except Exception as e:
        print_error(f"API Gateway creation failed: {e}")
        return None


def main():
    """Main deployment function."""
    print_status("=" * 70)
    print_status("[LAUNCH] COMPLIANCE GUARDIAN AI - LAMBDA DEPLOYMENT")
    print_status(f"   Environment: {ENVIRONMENT}")
    print_status(f"   Region: {REGION}")
    print_status("=" * 70)
    
    # Ensure S3 bucket exists for deployments
    ensure_s3_bucket()
    
    # Lambda functions to deploy
    functions = [
        {
            'name': f'{PROJECT_NAME}-orchestrator-{ENVIRONMENT}',
            'handler': 'src.agents.orchestrator.lambda_handler',
            'role': 'orchestrator-agent',
            'description': 'Orchestrator Agent - Coordinates multi-agent workflow',
            'timeout': 300,
            'memory': 512
        },
        {
            'name': f'{PROJECT_NAME}-compliance-{ENVIRONMENT}',
            'handler': 'src.agents.compliance_agent.lambda_handler',
            'role': 'compliance-agent',
            'description': 'Compliance Agent - Scans for regulatory violations',
            'timeout': 300,
            'memory': 1024
        },
        {
            'name': f'{PROJECT_NAME}-audit-{ENVIRONMENT}',
            'handler': 'src.agents.audit_agent.lambda_handler',
            'role': 'audit-agent',
            'description': 'Audit Agent - Generates compliance audit trails',
            'timeout': 300,
            'memory': 512
        },
        {
            'name': f'{PROJECT_NAME}-remediation-{ENVIRONMENT}',
            'handler': 'src.agents.remediation_agent.lambda_handler',
            'role': 'remediation-agent',
            'description': 'Remediation Agent - Auto-fixes compliance violations',
            'timeout': 300,
            'memory': 512
        },
        {
            'name': f'{PROJECT_NAME}-explainability-{ENVIRONMENT}',
            'handler': 'src.agents.explainability_agent.lambda_handler',
            'role': 'explainability-agent',
            'description': 'Explainability Agent - Explains compliance decisions',
            'timeout': 180,
            'memory': 512
        },
        {
            'name': f'{PROJECT_NAME}-api-{ENVIRONMENT}',
            'handler': 'src.api.main.lambda_handler',
            'role': 'api-handler',
            'description': 'API Handler - REST API endpoint for client requests',
            'timeout': 60,
            'memory': 256
        }
    ]
    
    deployed_functions = []
    
    try:
        # Step 1: Package and deploy each Lambda function
        for i, func_config in enumerate(functions, 1):
            print_status(f"\n{'='*70}")
            print_status(f"[{i}/{len(functions)}] Deploying {func_config['name']}")
            print_status('='*70)
            
            # Create deployment package
            zip_path = create_deployment_package(
                func_config['name'],
                func_config['handler']
            )
            
            # Get IAM role ARN
            role_arn = f"arn:aws:iam::{ACCOUNT_ID}:role/{PROJECT_NAME}-{func_config['role']}-{ENVIRONMENT}"
            
            # Deploy Lambda function
            function_name = create_lambda_function(
                function_name=func_config['name'],
                handler=func_config['handler'],
                role_arn=role_arn,
                zip_path=zip_path,
                description=func_config['description'],
                timeout=func_config['timeout'],
                memory=func_config['memory']
            )
            
            deployed_functions.append(function_name)
            
            # Cleanup ZIP file
            if os.path.exists(zip_path):
                os.remove(zip_path)
        
        # Step 2: Create API Gateway
        api_url = create_api_gateway()
        
        # Step 3: Save deployment info
        deployment_info = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'environment': ENVIRONMENT,
            'region': REGION,
            'account_id': ACCOUNT_ID,
            'functions': deployed_functions,
            'api_url': api_url,
            'api_endpoint': f"{api_url}/scan" if api_url else None
        }
        
        with open('deployment_info.json', 'w') as f:
            json.dump(deployment_info, f, indent=2)
        
        print_status("\n" + "=" * 70)
        print_success("[CELEBRATE] LAMBDA DEPLOYMENT COMPLETE!")
        print_status("=" * 70)
        
        print_status("\n[LIST] DEPLOYED FUNCTIONS:")
        for func_name in deployed_functions:
            print_status(f"   [OK] {func_name}")
        
        if api_url:
            print_status(f"\n[WEB] API ENDPOINT:")
            print_status(f"   {api_url}/scan")
            print_status(f"\n[IDEA] Test with:")
            print_status(f'   curl -X POST {api_url}/scan -H "Content-Type: application/json" -d \'{{"scan_type": "GDPR", "target": "test-data"}}\'')
        
        print_status(f"\n[STATS] NEXT STEPS:")
        print_status(f"   1. Test the API endpoint")
        print_status(f"   2. Check CloudWatch logs for any errors")
        print_status(f"   3. Run end-to-end workflow test")
        
        print_status(f"\n[MONEY] COST ESTIMATE:")
        print_status(f"   Deployment: ~$3-5")
        print_status(f"   Credits remaining: ~$93-95 of $100")
        
    except Exception as e:
        print_error(f"\n[BOOM] Deployment failed: {e}")
        import traceback
        traceback.print_exc()
        raise


if __name__ == "__main__":
    main()
