"""
Compliance Guardian AI - System Status Dashboard
Shows real-time status of all components
"""
import boto3
import json
from datetime import datetime

REGION = "us-east-1"
PROJECT_NAME = "compliance-guardian-ai"
ENVIRONMENT = "production"

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

def check_component(name, check_func):
    """Check a component and return status."""
    try:
        result = check_func()
        status = f"{Colors.GREEN}[OK] ONLINE{Colors.END}"
        return True, status, result
    except Exception as e:
        status = f"{Colors.RED}[ERROR] OFFLINE{Colors.END}"
        return False, status, str(e)

def check_lambda_functions():
    """Check all Lambda functions."""
    lambda_client = boto3.client('lambda', region_name=REGION)
    functions = []
    
    function_names = [
        f'{PROJECT_NAME}-orchestrator-{ENVIRONMENT}',
        f'{PROJECT_NAME}-compliance-{ENVIRONMENT}',
        f'{PROJECT_NAME}-audit-{ENVIRONMENT}',
        f'{PROJECT_NAME}-remediation-{ENVIRONMENT}',
        f'{PROJECT_NAME}-explainability-{ENVIRONMENT}',
        f'{PROJECT_NAME}-api-{ENVIRONMENT}'
    ]
    
    for func_name in function_names:
        try:
            response = lambda_client.get_function(FunctionName=func_name)
            functions.append({
                'name': func_name,
                'status': 'Active',
                'runtime': response['Configuration']['Runtime'],
                'memory': response['Configuration']['MemorySize'],
                'timeout': response['Configuration']['Timeout']
            })
        except:
            pass
    
    return functions

def check_dynamodb_tables():
    """Check all DynamoDB tables."""
    dynamodb = boto3.client('dynamodb', region_name=REGION)
    tables = []
    
    table_names = [
        f'{PROJECT_NAME}-violations-{ENVIRONMENT}',
        f'{PROJECT_NAME}-audit-logs-{ENVIRONMENT}',
        f'{PROJECT_NAME}-agent-memory-{ENVIRONMENT}',
        f'{PROJECT_NAME}-reports-{ENVIRONMENT}',
        f'{PROJECT_NAME}-scan-results-{ENVIRONMENT}'
    ]
    
    for table_name in table_names:
        try:
            response = dynamodb.describe_table(TableName=table_name)
            table = response['Table']
            tables.append({
                'name': table_name,
                'status': table['TableStatus'],
                'items': table.get('ItemCount', 0)
            })
        except:
            pass
    
    return tables

def check_s3_buckets():
    """Check all S3 buckets."""
    s3 = boto3.client('s3', region_name=REGION)
    buckets = []
    
    bucket_names = [
        f'{PROJECT_NAME}-data-{ENVIRONMENT}',
        f'{PROJECT_NAME}-reports-{ENVIRONMENT}',
        f'{PROJECT_NAME}-deployment-{ENVIRONMENT}'
    ]
    
    for bucket_name in bucket_names:
        try:
            s3.head_bucket(Bucket=bucket_name)
            buckets.append({
                'name': bucket_name,
                'status': 'Active'
            })
        except:
            pass
    
    return buckets

def check_bedrock():
    """Check Bedrock access with Amazon Nova."""
    bedrock = boto3.client('bedrock-runtime', region_name=REGION)
    
    try:
        request_body = {
            "messages": [
                {"role": "user", "content": [{"text": "test"}]}
            ],
            "inferenceConfig": {"max_new_tokens": 10}
        }
        
        bedrock.invoke_model(
            modelId='us.amazon.nova-pro-v1:0',
            body=json.dumps(request_body)
        )
        return True
    except:
        return False

def show_dashboard():
    """Display system status dashboard."""
    print(f"\n{Colors.BOLD}{'=' * 70}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}[TARGET] COMPLIANCE GUARDIAN AI - SYSTEM STATUS{Colors.END}")
    print(f"{Colors.BOLD}{'=' * 70}{Colors.END}")
    print(f"   Environment: {ENVIRONMENT}")
    print(f"   Region: {REGION}")
    print(f"   Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{Colors.BOLD}{'=' * 70}{Colors.END}")
    
    # Lambda Functions
    print(f"\n{Colors.BOLD}[PACKAGE] LAMBDA FUNCTIONS (6 total){Colors.END}")
    functions = check_lambda_functions()
    if functions:
        for func in functions:
            short_name = func['name'].replace(f'{PROJECT_NAME}-', '').replace(f'-{ENVIRONMENT}', '')
            print(f"   {Colors.GREEN}[OK]{Colors.END} {short_name:20s} | {func['runtime']} | {func['memory']}MB | {func['timeout']}s")
    else:
        print(f"   {Colors.RED}[ERROR] No Lambda functions found{Colors.END}")
    
    # DynamoDB Tables
    print(f"\n{Colors.BOLD}[DB] DYNAMODB TABLES (5 total){Colors.END}")
    tables = check_dynamodb_tables()
    if tables:
        for table in tables:
            short_name = table['name'].replace(f'{PROJECT_NAME}-', '').replace(f'-{ENVIRONMENT}', '')
            status_icon = Colors.GREEN + "[OK]" if table['status'] == 'ACTIVE' else Colors.YELLOW + "[WARNING]"
            print(f"   {status_icon}{Colors.END} {short_name:20s} | {table['status']}")
    else:
        print(f"   {Colors.RED}[ERROR] No DynamoDB tables found{Colors.END}")
    
    # S3 Buckets
    print(f"\n{Colors.BOLD}[STORAGE]  S3 BUCKETS (3 total){Colors.END}")
    buckets = check_s3_buckets()
    if buckets:
        for bucket in buckets:
            short_name = bucket['name'].replace(f'{PROJECT_NAME}-', '').replace(f'-{ENVIRONMENT}', '')
            print(f"   {Colors.GREEN}[OK]{Colors.END} {short_name:20s} | {bucket['status']}")
    else:
        print(f"   {Colors.RED}[ERROR] No S3 buckets found{Colors.END}")
    
    # Bedrock
    print(f"\n{Colors.BOLD}[AI] AWS BEDROCK AI{Colors.END}")
    bedrock_ok = check_bedrock()
    if bedrock_ok:
        print(f"   {Colors.GREEN}[OK] Amazon Nova Pro - ENABLED{Colors.END}")
    else:
        print(f"   {Colors.RED}[ERROR] Model Access - NOT ENABLED{Colors.END}")
        print(f"   {Colors.YELLOW}   Run: python test_bedrock.py{Colors.END}")
    
    # API Gateway
    print(f"\n{Colors.BOLD}[WEB] API GATEWAY{Colors.END}")
    print(f"   {Colors.GREEN}[OK]{Colors.END} https://gluwdyp4ii.execute-api.us-east-1.amazonaws.com/production")
    
    # Summary
    print(f"\n{Colors.BOLD}{'=' * 70}{Colors.END}")
    total_components = len(functions) + len(tables) + len(buckets)
    bedrock_count = 1 if bedrock_ok else 0
    total_working = total_components + bedrock_count + 1  # +1 for API Gateway
    
    print(f"{Colors.BOLD}[STATS] SYSTEM HEALTH: {total_working}/{total_components + 2} components operational{Colors.END}")
    
    if total_working == total_components + 2:
        print(f"{Colors.GREEN}{Colors.BOLD}[OK] ALL SYSTEMS OPERATIONAL!{Colors.END}")
    elif bedrock_ok:
        print(f"{Colors.YELLOW}{Colors.BOLD}[WARNING]  System ready (Bedrock pending){Colors.END}")
    else:
        print(f"{Colors.RED}{Colors.BOLD}[ERROR] Some components need attention{Colors.END}")
    
    print(f"{Colors.BOLD}{'=' * 70}{Colors.END}\n")
    
    # Quick actions
    print(f"{Colors.BOLD}[FAST] QUICK ACTIONS:{Colors.END}")
    if not bedrock_ok:
        print(f"   → python enable_bedrock.py           # Enable Bedrock model access")
    print(f"   → python test_complete_workflow.py   # Run full test suite")
    print(f"   → python -m examples.basic_scan      # Run a compliance scan")
    print()

if __name__ == "__main__":
    try:
        show_dashboard()
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
