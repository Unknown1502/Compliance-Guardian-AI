"""
Quick test script to verify Amazon Bedrock access with Claude 3.5 Sonnet v2.
Run this after configuring AWS CLI to confirm model access works.
"""
import json
import boto3
from botocore.exceptions import ClientError

def test_bedrock_claude():
    """Test connection to Amazon Nova Pro via Bedrock."""
    print("[TEST] Testing Amazon Bedrock connection with Nova Pro...")
    
    # Initialize Bedrock Runtime client
    bedrock_runtime = boto3.client(
        service_name='bedrock-runtime',
        region_name='us-east-1'
    )
    
    # Model ID for Amazon Nova Pro - No approval needed!
    model_id = "us.amazon.nova-pro-v1:0"
    
    # Test prompt
    prompt = "Say 'Hello from AWS Bedrock!' in exactly 5 words."
    
    # Prepare request body (Nova format - similar to Claude)
    request_body = {
        "messages": [
            {
                "role": "user",
                "content": [{"text": prompt}]
            }
        ],
        "inferenceConfig": {
            "max_new_tokens": 100,
            "temperature": 0.7
        }
    }
    
    try:
        print(f" Invoking model: {model_id}")
        print(f" Prompt: {prompt}")
        
        # Invoke the model
        response = bedrock_runtime.invoke_model(
            modelId=model_id,
            body=json.dumps(request_body)
        )
        
        # Parse response (Nova format)
        response_body = json.loads(response['body'].read())
        assistant_message = response_body['output']['message']['content'][0]['text']
        
        print(f"[OK] SUCCESS! Amazon Nova responded:")
        print(f"   {assistant_message}")
        print(f"\n[STATS] Token usage:")
        print(f"   Input: {response_body.get('usage', {}).get('inputTokens', 'N/A')} tokens")
        print(f"   Output: {response_body.get('usage', {}).get('outputTokens', 'N/A')} tokens")
        
        # Calculate cost (Nova Pro pricing - cheaper than Claude!)
        input_tokens = response_body.get('usage', {}).get('inputTokens', 0)
        output_tokens = response_body.get('usage', {}).get('outputTokens', 0)
        input_cost = (input_tokens / 1_000_000) * 0.80  # Nova Pro: $0.80 per 1M input tokens
        output_cost = (output_tokens / 1_000_000) * 3.20  # Nova Pro: $3.20 per 1M output tokens
        total_cost = input_cost + output_cost
        
        print(f"   Cost: ${total_cost:.6f} (${100 - total_cost:.2f} credits remaining)")
        print(f"\n[CELEBRATE] Bedrock + Nova Pro confirmed! System ready to deploy.")
        
        return True
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        print(f"[ERROR] ERROR: {error_code}")
        print(f"   {error_message}")
        
        if error_code == "AccessDeniedException":
            print("\n[TOOL] TROUBLESHOOTING:")
            print("   1. Verify AWS credentials: aws sts get-caller-identity")
            print("   2. Check IAM permissions include 'bedrock:InvokeModel'")
            print("   3. Confirm region is us-east-1 (Claude 3.5 Sonnet v2 available)")
        elif error_code == "ValidationException" and "use case" in error_message:
            print("\n[NOTE] ACTION REQUIRED:")
            print("   First-time Anthropic user detected. You need to:")
            print("   1. Go to AWS Console → Bedrock → Model catalog")
            print("   2. Find Claude 3.5 Sonnet v2")
            print("   3. Submit use case details (takes 5 minutes)")
            print("   4. Wait for approval (usually instant)")
        
        return False
        
    except Exception as e:
        print(f"[ERROR] UNEXPECTED ERROR: {type(e).__name__}")
        print(f"   {str(e)}")
        return False


def test_bedrock_nova():
    """Test connection to Amazon Nova Act."""
    print("\n[TEST] Testing Amazon Nova Act model...")
    
    bedrock_runtime = boto3.client(
        service_name='bedrock-runtime',
        region_name='us-east-1'
    )
    
    model_id = "amazon.nova-act-v1:0"
    
    try:
        print(f" Invoking model: {model_id}")
        
        # Nova uses different request format (check docs for exact format)
        # For now, just test that the model exists
        response = bedrock_runtime.invoke_model(
            modelId=model_id,
            body=json.dumps({
                "inputText": "Hello Nova",
                "textGenerationConfig": {
                    "maxTokenCount": 10,
                    "temperature": 0.5
                }
            })
        )
        
        print(f"[OK] Nova Act model access confirmed!")
        return True
        
    except ClientError as e:
        if "ResourceNotFoundException" in str(e):
            print(f"[WARNING]  Nova Act not yet available in us-east-1")
            print(f"   (This is OK - Claude 3.5 Sonnet is primary model)")
        else:
            print(f"[WARNING]  Nova test failed: {e.response['Error']['Code']}")
        return False


if __name__ == "__main__":
    print("=" * 60)
    print("[LAUNCH] COMPLIANCE GUARDIAN AI - BEDROCK CONNECTIVITY TEST")
    print("=" * 60)
    
    # Test Claude 3.5 Sonnet v2 (primary model)
    claude_success = test_bedrock_claude()
    
    # Test Nova Act (secondary model for agent actions)
    nova_success = test_bedrock_nova()
    
    print("\n" + "=" * 60)
    if claude_success:
        print("[OK] READY TO DEPLOY! AWS Bedrock is working correctly.")
        print("\n[LIST] NEXT STEPS:")
        print("   1. Update .env file with AWS credentials")
        print("   2. Run: bash scripts/setup_aws_resources.sh production")
        print("   3. Run: bash scripts/deploy.sh production")
    else:
        print("[ERROR] FIX BEDROCK ACCESS BEFORE PROCEEDING")
        print("   Review troubleshooting steps above")
    print("=" * 60)
