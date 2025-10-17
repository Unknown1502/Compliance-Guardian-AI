"""
Update all Lambda functions to use Amazon Nova model
"""
import boto3
import json

REGION = "us-east-1"
ENVIRONMENT = "production"
PROJECT_NAME = "compliance-guardian-ai"
NEW_MODEL_ID = "us.amazon.nova-pro-v1:0"

print("=" * 70)
print(" UPDATING LAMBDA FUNCTIONS TO USE AMAZON NOVA")
print("=" * 70)

lambda_client = boto3.client('lambda', region_name=REGION)

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
        # Get current environment variables
        response = lambda_client.get_function_configuration(FunctionName=func_name)
        env_vars = response.get('Environment', {}).get('Variables', {})
        
        # Update model ID
        env_vars['BEDROCK_MODEL_ID'] = NEW_MODEL_ID
        
        # Update the function
        lambda_client.update_function_configuration(
            FunctionName=func_name,
            Environment={'Variables': env_vars}
        )
        
        print(f"[OK] Updated {func_name}")
        print(f"   Model: {NEW_MODEL_ID}")
        
    except Exception as e:
        print(f"[ERROR] Failed to update {func_name}: {e}")

print("\n" + "=" * 70)
print("[OK] All Lambda functions updated to use Amazon Nova!")
print("=" * 70)

print("\n[NOTE] NEXT STEPS:")
print("   1. Run: python test_bedrock.py")
print("   2. Run: python test_complete_workflow.py")
print("   3. Test API: python -m examples.basic_scan")

print("\n[IDEA] Benefits of Amazon Nova:")
print("   • No approval forms required")
print("   • Faster response times")
print("   • Lower costs")
print("   • Native AWS integration")
print()
