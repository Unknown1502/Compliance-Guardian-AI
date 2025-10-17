"""
Simple Lambda handler that works without complex dependencies.
This is the main entry point for the API Lambda function.
"""
import json
import os
import boto3
from datetime import datetime

# Initialize Bedrock client
bedrock = boto3.client('bedrock-runtime', region_name=os.environ.get('AWS_REGION', 'us-east-1'))


def lambda_handler(event, context):
    """
    Simple Lambda handler for scan endpoint.
    
    Args:
        event: API Gateway proxy event
        context: Lambda context
    
    Returns:
        API Gateway proxy response
    """
    try:
        # Parse request body
        if 'body' in event:
            body = json.loads(event['body']) if isinstance(event['body'], str) else event['body']
        else:
            body = event
        
        scan_type = body.get('scan_type', 'GDPR')
        target = body.get('target', 'unknown')
        scope = body.get('scope', [])
        
        # Call Bedrock to analyze compliance
        try:
            prompt = f"""You are a compliance expert. Analyze this scan request:
- Scan Type: {scan_type}
- Target: {target}
- Scope: {', '.join(scope) if scope else 'general'}

Provide a brief compliance analysis and identify any potential violations."""

            bedrock_response = bedrock.invoke_model(
                modelId='us.amazon.nova-pro-v1:0',
                body=json.dumps({
                    "messages": [{"role": "user", "content": [{"text": prompt}]}],
                    "inferenceConfig": {
                        "max_new_tokens": 500,
                        "temperature": 0.1
                    }
                })
            )
            
            response_body = json.loads(bedrock_response['body'].read())
            ai_analysis = response_body.get('output', {}).get('message', {}).get('content', [{}])[0].get('text', 'Analysis complete')
            
        except Exception as bedrock_error:
            print(f"Bedrock error: {bedrock_error}")
            ai_analysis = f"Bedrock analysis unavailable: {str(bedrock_error)}"
        
        # Generate scan response
        response_data = {
            'status': 'completed',
            'scan_id': f"scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            'scan_type': scan_type,
            'target': target,
            'scope': scope,
            'timestamp': datetime.now().isoformat(),
            'violations_found': 0,  # Simplified - would be populated by actual scanners
            'analysis': ai_analysis,
            'recommendations': [
                f"Review {scan_type} compliance requirements",
                "Implement data encryption at rest",
                "Enable audit logging",
                "Configure access controls"
            ]
        }
        
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type'
            },
            'body': json.dumps(response_data)
        }
        
    except Exception as e:
        print(f"Error: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'error': 'Internal server error',
                'message': str(e)
            })
        }


# For local testing
if __name__ == "__main__":
    test_event = {
        'body': json.dumps({
            'scan_type': 'GDPR',
            'target': 'test-app',
            'scope': ['data_privacy', 'encryption']
        })
    }
    
    result = lambda_handler(test_event, None)
    print(json.dumps(json.loads(result['body']), indent=2))
