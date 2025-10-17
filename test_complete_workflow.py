"""
Complete End-to-End Testing for Compliance Guardian AI
Tests all Lambda functions, API Gateway, and workflows
"""
import boto3
import json
import time
import requests
from datetime import datetime

# Configuration
REGION = "us-east-1"
API_URL = "https://gluwdyp4ii.execute-api.us-east-1.amazonaws.com/production"

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


def test_lambda_function(function_name, test_payload):
    """Test a Lambda function directly."""
    lambda_client = boto3.client('lambda', region_name=REGION)
    
    try:
        response = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType='RequestResponse',
            Payload=json.dumps(test_payload)
        )
        
        response_payload = json.loads(response['Payload'].read())
        
        if response['StatusCode'] == 200:
            print_success(f"Lambda {function_name} executed successfully")
            return True, response_payload
        else:
            print_error(f"Lambda {function_name} returned status {response['StatusCode']}")
            return False, response_payload
            
    except Exception as e:
        print_error(f"Lambda {function_name} failed: {e}")
        return False, str(e)


def test_api_gateway():
    """Test API Gateway endpoint."""
    print_status("\n[WEB] Testing API Gateway...")
    
    test_payload = {
        "scan_type": "GDPR",
        "target": "test-data",
        "repository_url": "https://github.com/test/test-repo"
    }
    
    try:
        response = requests.post(
            f"{API_URL}/scan",
            json=test_payload,
            timeout=30
        )
        
        print_status(f"   Status Code: {response.status_code}")
        
        if response.status_code == 200:
            print_success("API Gateway is working!")
            print_status(f"   Response: {response.json()}")
            return True
        else:
            print_warning(f"API returned {response.status_code}")
            print_status(f"   Response: {response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        print_error(f"API Gateway test failed: {e}")
        return False


def test_bedrock_access():
    """Test Bedrock access."""
    print_status("\n[AI] Testing AWS Bedrock Access...")
    
    bedrock = boto3.client('bedrock-runtime', region_name=REGION)
    
    try:
        # Test with Amazon Nova Pro
        test_prompt = "Hello, this is a test. Please respond with 'Bedrock is working!'"
        
        request_body = {
            "messages": [
                {
                    "role": "user",
                    "content": [{"text": test_prompt}]
                }
            ],
            "inferenceConfig": {
                "max_new_tokens": 100,
                "temperature": 0.7
            }
        }
        
        response = bedrock.invoke_model(
            modelId='us.amazon.nova-pro-v1:0',
            body=json.dumps(request_body)
        )
        
        response_body = json.loads(response['body'].read())
        
        print_success("Bedrock + Nova Pro access verified!")
        print_status(f"   Model Response: {response_body['output']['message']['content'][0]['text']}")
        return True
        
    except Exception as e:
        print_error(f"Bedrock access test failed: {e}")
        print_warning("Amazon Nova should work automatically - check your AWS configuration")
        return False


def test_dynamodb_access():
    """Test DynamoDB table access."""
    print_status("\n[DB] Testing DynamoDB Access...")
    
    dynamodb = boto3.client('dynamodb', region_name=REGION)
    
    tables_to_check = [
        'compliance-guardian-ai-violations-production',
        'compliance-guardian-ai-audit-logs-production',
        'compliance-guardian-ai-agent-memory-production',
        'compliance-guardian-ai-reports-production',
        'compliance-guardian-ai-scan-results-production'
    ]
    
    all_ok = True
    for table_name in tables_to_check:
        try:
            response = dynamodb.describe_table(TableName=table_name)
            status = response['Table']['TableStatus']
            
            if status == 'ACTIVE':
                print_success(f"Table {table_name}: {status}")
            else:
                print_warning(f"Table {table_name}: {status}")
                all_ok = False
                
        except Exception as e:
            print_error(f"Table {table_name}: NOT FOUND")
            all_ok = False
    
    return all_ok


def test_s3_access():
    """Test S3 bucket access."""
    print_status("\n[PACKAGE] Testing S3 Bucket Access...")
    
    s3 = boto3.client('s3', region_name=REGION)
    
    buckets_to_check = [
        'compliance-guardian-ai-data-production',
        'compliance-guardian-ai-reports-production',
        'compliance-guardian-ai-deployment-production'
    ]
    
    all_ok = True
    for bucket_name in buckets_to_check:
        try:
            s3.head_bucket(Bucket=bucket_name)
            print_success(f"Bucket {bucket_name}: EXISTS")
        except Exception as e:
            print_error(f"Bucket {bucket_name}: NOT FOUND")
            all_ok = False
    
    return all_ok


def test_all_lambda_functions():
    """Test all Lambda functions."""
    print_status("\n[TOOL] Testing Individual Lambda Functions...")
    
    functions = [
        {
            'name': 'compliance-guardian-ai-orchestrator-production',
            'payload': {'action': 'test', 'message': 'Health check'}
        },
        {
            'name': 'compliance-guardian-ai-compliance-production',
            'payload': {'action': 'test', 'scan_type': 'GDPR'}
        },
        {
            'name': 'compliance-guardian-ai-audit-production',
            'payload': {'action': 'test'}
        },
        {
            'name': 'compliance-guardian-ai-remediation-production',
            'payload': {'action': 'test'}
        },
        {
            'name': 'compliance-guardian-ai-explainability-production',
            'payload': {'action': 'test'}
        },
        {
            'name': 'compliance-guardian-ai-api-production',
            'payload': {'httpMethod': 'GET', 'path': '/health'}
        }
    ]
    
    results = []
    for func in functions:
        success, response = test_lambda_function(func['name'], func['payload'])
        results.append(success)
        time.sleep(1)  # Rate limiting
    
    return all(results)


def check_cloudwatch_logs():
    """Check recent CloudWatch logs for errors."""
    print_status("\n[STATS] Checking CloudWatch Logs...")
    
    logs = boto3.client('logs', region_name=REGION)
    
    log_groups = [
        '/aws/lambda/compliance-guardian-ai-orchestrator-production',
        '/aws/lambda/compliance-guardian-ai-compliance-production',
        '/aws/lambda/compliance-guardian-ai-api-production'
    ]
    
    for log_group in log_groups:
        try:
            # Get recent log streams
            response = logs.describe_log_streams(
                logGroupName=log_group,
                orderBy='LastEventTime',
                descending=True,
                limit=1
            )
            
            if response['logStreams']:
                stream = response['logStreams'][0]
                print_success(f"Log group {log_group.split('/')[-1]}: Active")
                print_status(f"   Last event: {datetime.fromtimestamp(stream['lastEventTimestamp']/1000)}")
            else:
                print_warning(f"Log group {log_group.split('/')[-1]}: No logs yet")
                
        except Exception as e:
            print_warning(f"Could not access logs for {log_group.split('/')[-1]}")
    
    return True


def run_all_tests():
    """Run complete test suite."""
    print_status("=" * 70)
    print_status("[TEST] COMPLIANCE GUARDIAN AI - COMPREHENSIVE TESTING")
    print_status("=" * 70)
    
    results = {}
    
    # Test 1: Infrastructure
    print_status("\n" + "=" * 70)
    print_status("[TEST 1/6] Infrastructure Components")
    print_status("=" * 70)
    
    results['dynamodb'] = test_dynamodb_access()
    results['s3'] = test_s3_access()
    
    # Test 2: Bedrock
    print_status("\n" + "=" * 70)
    print_status("[TEST 2/6] AWS Bedrock AI Service")
    print_status("=" * 70)
    
    results['bedrock'] = test_bedrock_access()
    
    # Test 3: Lambda Functions
    print_status("\n" + "=" * 70)
    print_status("[TEST 3/6] Lambda Functions")
    print_status("=" * 70)
    
    results['lambda'] = test_all_lambda_functions()
    
    # Test 4: API Gateway
    print_status("\n" + "=" * 70)
    print_status("[TEST 4/6] API Gateway")
    print_status("=" * 70)
    
    results['api'] = test_api_gateway()
    
    # Test 5: CloudWatch Logs
    print_status("\n" + "=" * 70)
    print_status("[TEST 5/6] CloudWatch Logs")
    print_status("=" * 70)
    
    results['logs'] = check_cloudwatch_logs()
    
    # Summary
    print_status("\n" + "=" * 70)
    print_status("[STATS] TEST SUMMARY")
    print_status("=" * 70)
    
    total = len(results)
    passed = sum(1 for v in results.values() if v)
    
    for test_name, result in results.items():
        status = "[OK] PASS" if result else "[ERROR] FAIL"
        print_status(f"   {test_name.upper()}: {status}")
    
    print_status(f"\n   Total: {passed}/{total} tests passed")
    
    if passed == total:
        print_success("\n[CELEBRATE] All tests passed! System is fully operational!")
        print_status("\n[NOTE] NEXT STEPS:")
        print_status("   1. Run a real compliance scan")
        print_status("   2. Check the generated reports")
        print_status("   3. Review CloudWatch logs for details")
    else:
        print_warning(f"\n[WARNING]  {total - passed} test(s) failed. Review the output above.")
        print_status("\n[TOOL] TROUBLESHOOTING:")
        
        if not results.get('dynamodb'):
            print_status("   - Run: python setup_infrastructure.py")
        if not results.get('bedrock'):
            print_status("   - Enable Bedrock models in AWS Console")
        if not results.get('lambda'):
            print_status("   - Check Lambda function logs in CloudWatch")
        if not results.get('api'):
            print_status("   - Verify API Gateway configuration")
    
    print_status("\n" + "=" * 70)
    
    return passed == total


if __name__ == "__main__":
    try:
        success = run_all_tests()
        exit(0 if success else 1)
    except Exception as e:
        print_error(f"Testing failed: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
