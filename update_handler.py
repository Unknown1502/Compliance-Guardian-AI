"""Update Lambda handler configuration after deployment"""
import boto3
import time
import json

lambda_client = boto3.client('lambda')
function_name = 'compliance-guardian-ai-api-production'

print("[INFO] Waiting for Lambda to be ready...")
time.sleep(10)

print(f"[OK] Updating handler for {function_name}...")
try:
    lambda_client.update_function_configuration(
        FunctionName=function_name,
        Handler='lambda_handler.lambda_handler'
    )
    print("[OK] Handler updated successfully!")
    
    # Wait a bit
    time.sleep(5)
    
    # Test it
    print("\n[TEST] Testing function...")
    test_event = {
        'httpMethod': 'POST',
        'path': '/scan',
        'body': json.dumps({
            'scan_type': 'PCI DSS',
            'target': 'payment-system',
            'scope': ['card_data', 'encryption']
        })
    }
    
    response = lambda_client.invoke(
        FunctionName=function_name,
        InvocationType='RequestResponse',
        Payload=json.dumps(test_event)
    )
    
    result = json.loads(response['Payload'].read())
    print(f"Status: {result.get('statusCode')}")
    
    if result.get('statusCode') == 200:
        body = json.loads(result.get('body', '{}'))
        print(f"[OK] Scan ID: {body.get('scan_id')}")
        print(f"[OK] Working correctly!")
    else:
        print(f"[WARNING] Response: {json.dumps(result, indent=2)}")
        
except Exception as e:
    print(f"[ERROR] {e}")
