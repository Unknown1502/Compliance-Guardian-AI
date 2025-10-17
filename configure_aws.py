"""
Configure AWS credentials without AWS CLI.
Creates ~/.aws/credentials and ~/.aws/config files.
"""
import os
from pathlib import Path

def configure_aws_credentials():
    """Manually configure AWS credentials."""
    print("=" * 60)
    print("[SECURE] AWS CREDENTIALS CONFIGURATION")
    print("=" * 60)
    
    # Get credentials from user
    print("\nEnter your AWS credentials (from IAM Console):")
    access_key = input("AWS Access Key ID: ").strip()
    secret_key = input("AWS Secret Access Key: ").strip()
    region = input("Default region [us-east-1]: ").strip() or "us-east-1"
    
    # Create .aws directory
    aws_dir = Path.home() / ".aws"
    aws_dir.mkdir(exist_ok=True)
    
    # Write credentials file
    credentials_file = aws_dir / "credentials"
    with open(credentials_file, 'w') as f:
        f.write("[default]\n")
        f.write(f"aws_access_key_id = {access_key}\n")
        f.write(f"aws_secret_access_key = {secret_key}\n")
    
    print(f"[OK] Created: {credentials_file}")
    
    # Write config file
    config_file = aws_dir / "config"
    with open(config_file, 'w') as f:
        f.write("[default]\n")
        f.write(f"region = {region}\n")
        f.write("output = json\n")
    
    print(f"[OK] Created: {config_file}")
    
    # Verify credentials work
    print("\n[TEST] Testing credentials...")
    try:
        import boto3
        sts = boto3.client('sts')
        identity = sts.get_caller_identity()
        
        print(f"[OK] SUCCESS! Credentials validated.")
        print(f"\n[LIST] Your AWS Account Details:")
        print(f"   Account ID: {identity['Account']}")
        print(f"   User ARN: {identity['Arn']}")
        print(f"   Region: {region}")
        print(f"\n[CELEBRATE] AWS credentials configured successfully!")
        print(f"\n[NOTE] NEXT STEP: Run 'python test_bedrock.py' to test Bedrock access")
        
        return True
        
    except Exception as e:
        print(f"[ERROR] ERROR testing credentials: {e}")
        print(f"\n[TOOL] Double-check your Access Key ID and Secret Access Key")
        return False

if __name__ == "__main__":
    configure_aws_credentials()
