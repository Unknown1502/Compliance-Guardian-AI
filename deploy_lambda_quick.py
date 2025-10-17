"""
Quick Lambda deployment script for the API function
"""
import boto3
import zipfile
import os
from pathlib import Path
import time

def create_lambda_package():
    """Create a deployment package for Lambda."""
    print("[PACKAGE] Creating Lambda deployment package...")
    
    zip_path = 'lambda_deployment.zip'
    
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # Add the handler
        zipf.write('lambda_handler.py', 'lambda_handler.py')
        print("   Added: lambda_handler.py")
    
    file_size = os.path.getsize(zip_path) / 1024
    print(f"   [OK] Package created: {zip_path} ({file_size:.1f} KB)")
    return zip_path


def update_lambda_function(zip_path):
    """Update the Lambda function with new code."""
    lambda_client = boto3.client('lambda')
    function_name = 'compliance-guardian-ai-api-production'
    
    print(f"\n[UPLOAD] Updating Lambda function: {function_name}")
    
    try:
        with open(zip_path, 'rb') as f:
            zip_content = f.read()
        
        response = lambda_client.update_function_code(
            FunctionName=function_name,
            ZipFile=zip_content
        )
        
        print(f"   [OK] Function updated successfully!")
        print(f"   Function ARN: {response['FunctionArn']}")
        print(f"   Runtime: {response['Runtime']}")
        print(f"   Handler: {response['Handler']}")
        print(f"   Code Size: {response['CodeSize']} bytes")
        print(f"   Last Modified: {response['LastModified']}")
        
        # Update handler to point to the new file
        print(f"\n[OK] Updating handler configuration...")
        lambda_client.update_function_configuration(
            FunctionName=function_name,
            Handler='lambda_handler.lambda_handler'  # file.function
        )
        print("   [OK] Handler updated to: lambda_handler.lambda_handler")
        
        return True
        
    except Exception as e:
        print(f"   [ERROR] {e}")
        return False


def test_deployed_function():
    """Test the deployed Lambda function."""
    lambda_client = boto3.client('lambda')
    function_name = 'compliance-guardian-ai-api-production'
    
    print(f"\n[TEST] Testing deployed function...")
    
    import json
    test_event = {
        'httpMethod': 'POST',
        'path': '/scan',
        'body': json.dumps({
            'scan_type': 'HIPAA',
            'target': 'healthcare-app',
            'scope': ['phi_protection', 'encryption']
        })
    }
    
    try:
        response = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType='RequestResponse',
            Payload=json.dumps(test_event)
        )
        
        response_payload = json.loads(response['Payload'].read())
        status_code = response_payload.get('statusCode', 500)
        
        print(f"   Status Code: {status_code}")
        
        if status_code == 200:
            print("   [OK] Lambda working correctly!")
            body = json.loads(response_payload.get('body', '{}'))
            print(f"   Scan ID: {body.get('scan_id')}")
            print(f"   Scan Type: {body.get('scan_type')}")
            print(f"   Analysis: {body.get('analysis', '')[:100]}...")
            return True
        else:
            print(f"   [WARNING] Got status {status_code}")
            print(f"   Response: {json.dumps(response_payload, indent=2)}")
            return False
            
    except Exception as e:
        print(f"   [ERROR] {e}")
        return False


def main():
    print("=" * 70)
    print("[LAUNCH] QUICK LAMBDA DEPLOYMENT")
    print("=" * 70)
    
    # Step 1: Create package
    zip_path = create_lambda_package()
    
    # Step 2: Update Lambda
    if update_lambda_function(zip_path):
        # Step 3: Wait for deployment
        print("\n[INFO] Waiting 5 seconds for deployment to propagate...")
        time.sleep(5)
        
        # Step 4: Test
        test_deployed_function()
    
    # Cleanup
    if os.path.exists(zip_path):
        os.remove(zip_path)
        print(f"\n[OK] Cleaned up: {zip_path}")
    
    print("\n=" * 70)
    print("[OK] DEPLOYMENT COMPLETE!")
    print("=" * 70)
    print("\n[LIST] NEXT STEPS:")
    print("   1. Test API Gateway endpoint:")
    print("      python test_scan_endpoint.py")
    print("   2. Try in browser:")
    print("      https://gluwdyp4ii.execute-api.us-east-1.amazonaws.com/production/scan")


if __name__ == "__main__":
    main()
