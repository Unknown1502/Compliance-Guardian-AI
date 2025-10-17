"""
Simple Lambda handler for /scan endpoint
Bypasses FastAPI to avoid binary dependency issues
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
        
        # Simple response - scan initiated
        response_data = {
            'status': 'initiated',
            'scan_id': f"scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            'scan_type': scan_type,
            'target': target,
            'message': f'{scan_type} compliance scan initiated for {target}',
            'timestamp': datetime.now().isoformat()
        }
        
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps(response_data)
        }
        
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'error': str(e),
                'message': 'Internal server error'
            })
        }
