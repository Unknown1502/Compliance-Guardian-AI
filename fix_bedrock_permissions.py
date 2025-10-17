"""
Script to diagnose and fix Bedrock permissions for Lambda functions
"""
import boto3
import json
from botocore.exceptions import ClientError

def check_and_fix_bedrock_permissions():
    """Check Lambda IAM role and add Bedrock permissions if missing."""
    
    iam = boto3.client('iam')
    lambda_client = boto3.client('lambda')
    
    role_name = 'compliance-guardian-ai-lambda-role-production'
    
    print("=" * 70)
    print("[TOOL] BEDROCK PERMISSIONS DIAGNOSTIC & FIX")
    print("=" * 70)
    
    try:
        # 1. Check if role exists
        print("\n[1] Checking IAM Role...")
        role = iam.get_role(RoleName=role_name)
        print(f"   [OK] Role found: {role['Role']['RoleName']}")
        print(f"   ARN: {role['Role']['Arn']}")
        
        # 2. List attached policies
        print("\n[2] Checking attached policies...")
        policies = iam.list_attached_role_policies(RoleName=role_name)
        print(f"   Found {len(policies['AttachedPolicies'])} attached policies:")
        for policy in policies['AttachedPolicies']:
            print(f"      - {policy['PolicyName']}")
        
        # 3. Check inline policies
        print("\n[3] Checking inline policies...")
        inline_policies = iam.list_role_policies(RoleName=role_name)
        if inline_policies['PolicyNames']:
            print(f"   Found {len(inline_policies['PolicyNames'])} inline policies:")
            for policy_name in inline_policies['PolicyNames']:
                print(f"      - {policy_name}")
                # Get policy document
                policy_doc = iam.get_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name
                )
                policy_json = policy_doc['PolicyDocument']
                
                # Check if Bedrock is in the policy
                has_bedrock = False
                for statement in policy_json.get('Statement', []):
                    actions = statement.get('Action', [])
                    if isinstance(actions, str):
                        actions = [actions]
                    if any('bedrock' in action.lower() for action in actions):
                        has_bedrock = True
                        break
                
                if has_bedrock:
                    print(f"         [OK] Has Bedrock permissions")
                else:
                    print(f"         [WARNING] No Bedrock permissions found")
        else:
            print("   [WARNING] No inline policies found")
        
        # 4. Check if Bedrock permission exists
        print("\n[4] Checking for Bedrock permissions...")
        has_bedrock_permission = False
        
        # Check attached policies
        for policy in policies['AttachedPolicies']:
            if 'bedrock' in policy['PolicyName'].lower():
                has_bedrock_permission = True
                print(f"   [OK] Found Bedrock policy: {policy['PolicyName']}")
        
        # Check inline policies
        for policy_name in inline_policies.get('PolicyNames', []):
            policy_doc = iam.get_role_policy(
                RoleName=role_name,
                PolicyName=policy_name
            )
            policy_json = policy_doc['PolicyDocument']
            
            for statement in policy_json.get('Statement', []):
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                if any('bedrock' in action.lower() for action in actions):
                    has_bedrock_permission = True
                    print(f"   [OK] Found Bedrock permissions in policy: {policy_name}")
        
        # 5. Add Bedrock permissions if missing
        if not has_bedrock_permission:
            print("\n[5] [WARNING] No Bedrock permissions found. Adding them now...")
            
            bedrock_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "bedrock:InvokeModel",
                            "bedrock:InvokeModelWithResponseStream",
                            "bedrock:GetFoundationModel",
                            "bedrock:ListFoundationModels"
                        ],
                        "Resource": "*"
                    }
                ]
            }
            
            try:
                iam.put_role_policy(
                    RoleName=role_name,
                    PolicyName='BedrockAccess',
                    PolicyDocument=json.dumps(bedrock_policy)
                )
                print("   [OK] Successfully added Bedrock permissions!")
                print("   Added actions:")
                print("      - bedrock:InvokeModel")
                print("      - bedrock:InvokeModelWithResponseStream")
                print("      - bedrock:GetFoundationModel")
                print("      - bedrock:ListFoundationModels")
                return True
            except ClientError as e:
                print(f"   [ERROR] Failed to add permissions: {e}")
                return False
        else:
            print("\n[5] [OK] Bedrock permissions already exist!")
            return True
        
    except ClientError as e:
        print(f"\n[ERROR] {e}")
        return False
    
    print("\n" + "=" * 70)
    print("[OK] Permissions check complete!")
    print("=" * 70)


def test_lambda_bedrock_access():
    """Test if Lambda can actually invoke Bedrock."""
    lambda_client = boto3.client('lambda')
    
    print("\n" + "=" * 70)
    print("[TEST] Testing Lambda Bedrock Access")
    print("=" * 70)
    
    function_name = 'compliance-guardian-ai-api-production'
    
    # Test payload
    test_event = {
        'httpMethod': 'POST',
        'path': '/scan',
        'body': json.dumps({
            'scan_type': 'GDPR',
            'target': 'test-repository',
            'scope': ['data_privacy']
        })
    }
    
    try:
        print(f"\n[TEST] Invoking Lambda: {function_name}")
        response = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType='RequestResponse',
            Payload=json.dumps(test_event)
        )
        
        # Read response
        response_payload = json.loads(response['Payload'].read())
        status_code = response_payload.get('statusCode', 500)
        
        print(f"   Status Code: {status_code}")
        
        if status_code == 200:
            print("   [OK] Lambda executed successfully!")
            body = json.loads(response_payload.get('body', '{}'))
            print(f"   Response: {json.dumps(body, indent=2)}")
            return True
        else:
            print(f"   [WARNING] Lambda returned error")
            print(f"   Response: {json.dumps(response_payload, indent=2)}")
            return False
            
    except Exception as e:
        print(f"   [ERROR] {e}")
        return False


if __name__ == "__main__":
    # Step 1: Check and fix permissions
    permissions_ok = check_and_fix_bedrock_permissions()
    
    # Step 2: Wait a moment for IAM to propagate
    if permissions_ok:
        print("\n[INFO] Waiting 5 seconds for IAM changes to propagate...")
        import time
        time.sleep(5)
        
        # Step 3: Test Lambda
        test_lambda_bedrock_access()
    
    print("\n[LIST] NEXT STEPS:")
    print("   1. Test API endpoint: python test_scan_endpoint.py")
    print("   2. If still 502, check Lambda logs in CloudWatch")
    print("   3. Verify Bedrock model access in AWS Console")
