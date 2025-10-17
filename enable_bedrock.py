"""
Request AWS Bedrock Model Access
Opens the AWS Console page to enable Anthropic Claude models
"""
import webbrowser
import boto3

print("=" * 70)
print("[AI] AWS BEDROCK MODEL ACCESS SETUP")
print("=" * 70)

print("\n[LIST] You need to enable Anthropic Claude 3.5 Sonnet model access.")
print("\n[TOOL] STEPS:")
print("   1. Open AWS Console → Bedrock → Model Access")
print("   2. Click 'Modify model access'")
print("   3. Check the box for 'Anthropic Claude 3.5 Sonnet'")
print("   4. Submit the request")
print("   5. Wait ~2-5 minutes for approval")

print("\n[WEB] Opening AWS Bedrock Console...")

# Get region
try:
    session = boto3.Session()
    region = session.region_name or 'us-east-1'
except:
    region = 'us-east-1'

# Open Bedrock console
bedrock_url = f"https://{region}.console.aws.amazon.com/bedrock/home?region={region}#/modelaccess"
webbrowser.open(bedrock_url)

print(f"[OK] Opened: {bedrock_url}")
print("\n⏱  After enabling access, wait 2-5 minutes then run:")
print("   python test_complete_workflow.py")

print("\n" + "=" * 70)
