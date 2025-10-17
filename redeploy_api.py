"""
Deploy only the API Lambda function with FastAPI dependencies
"""
import boto3
import os
import shutil
import zipfile
from pathlib import Path
from botocore.config import Config

# Configuration
REGION = "us-east-1"
PROJECT_NAME = "compliance-guardian-ai"
ENVIRONMENT = "production"
DEPLOYMENT_BUCKET = f"{PROJECT_NAME}-deployment-{ENVIRONMENT}"
FUNCTION_NAME = f"{PROJECT_NAME}-api-{ENVIRONMENT}"

boto_config = Config(
    region_name=REGION,
    retries={'max_attempts': 10, 'mode': 'adaptive'},
    max_pool_connections=50,
    connect_timeout=300,
    read_timeout=300
)

def create_package():
    """Create deployment package for API Lambda."""
    print("[INFO] Creating API Lambda package...")
    
    package_dir = Path("temp_api_package")
    if package_dir.exists():
        shutil.rmtree(package_dir)
    package_dir.mkdir()
    
    try:
        # Copy src directory
        print("  [STEP 1/3] Copying src/...")
        shutil.copytree("src", package_dir / "src", ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        
        # Install dependencies
        print("  [STEP 2/3] Installing dependencies from requirements-lambda.txt...")
        os.system(f'pip install -r requirements-lambda.txt -t "{package_dir}" --quiet --upgrade --no-cache-dir')
        
        # Create ZIP
        zip_path = f"{FUNCTION_NAME}.zip"
        print(f"  [STEP 3/3] Creating {zip_path}...")
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(package_dir):
                dirs[:] = [d for d in dirs if d != '__pycache__']
                for file in files:
                    if file.endswith('.pyc'):
                        continue
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, package_dir)
                    zipf.write(file_path, arcname)
        
        zip_size_mb = os.path.getsize(zip_path) / (1024 * 1024)
        print(f"[SUCCESS] Package created: {zip_size_mb:.1f} MB")
        
        return zip_path
        
    finally:
        if package_dir.exists():
            shutil.rmtree(package_dir)


def upload_to_s3(zip_path):
    """Upload to S3."""
    s3_client = boto3.client('s3', config=boto_config)
    s3_key = f"lambda-deployments/{FUNCTION_NAME}/{os.path.basename(zip_path)}"
    
    print(f"[INFO] Uploading to S3: s3://{DEPLOYMENT_BUCKET}/{s3_key}")
    s3_client.upload_file(zip_path, DEPLOYMENT_BUCKET, s3_key)
    print("[SUCCESS] Upload complete")
    
    return s3_key


def update_lambda(s3_key):
    """Update Lambda function code."""
    lambda_client = boto3.client('lambda', config=boto_config)
    
    print(f"[INFO] Updating Lambda function: {FUNCTION_NAME}")
    
    response = lambda_client.update_function_code(
        FunctionName=FUNCTION_NAME,
        S3Bucket=DEPLOYMENT_BUCKET,
        S3Key=s3_key
    )
    
    print("[SUCCESS] Lambda updated successfully")
    print(f"  Version: {response['Version']}")
    print(f"  Last Modified: {response['LastModified']}")
    
    # Wait for update to complete
    print("[INFO] Waiting for update to complete...")
    waiter = lambda_client.get_waiter('function_updated')
    waiter.wait(FunctionName=FUNCTION_NAME)
    print("[SUCCESS] Function update complete")


def main():
    """Main deployment."""
    print("=" * 70)
    print("REDEPLOYING API LAMBDA WITH FASTAPI")
    print("=" * 70)
    
    try:
        # Create package
        zip_path = create_package()
        
        # Upload to S3
        s3_key = upload_to_s3(zip_path)
        
        # Update Lambda
        update_lambda(s3_key)
        
        # Cleanup
        if os.path.exists(zip_path):
            os.remove(zip_path)
        
        print("\n" + "=" * 70)
        print("API LAMBDA REDEPLOYMENT COMPLETE")
        print("=" * 70)
        print("\n[INFO] Test the API:")
        print('   $body = \'{"scan_type": "GDPR", "target": "test"}\'')
        print('   Invoke-RestMethod -Method Post -Uri "https://gluwdyp4ii.execute-api.us-east-1.amazonaws.com/production/scan" -Body $body -ContentType "application/json"')
        
    except Exception as e:
        print(f"\n[ERROR] Deployment failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
