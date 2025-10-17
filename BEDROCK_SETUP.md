# How to Enable AWS Bedrock Model Access

## Step 1: Open AWS Bedrock Console

1. Go to: https://us-east-1.console.aws.amazon.com/bedrock/home?region=us-east-1#/modelaccess
2. Sign in with your AWS account

## Step 2: Request Model Access

1. Click **"Edit"** or **"Modify model access"** button
2. Find **"Anthropic"** in the list
3. Check the box for **"Claude 3.5 Sonnet v2"**
4. Scroll down and click **"Request model access"** or **"Save changes"**

## Step 3: Fill Out Use Case Form (if required)

If prompted, fill out the Anthropic use case form:
- **Use Case**: Compliance scanning and regulatory analysis
- **Description**: Automated compliance checking for GDPR, HIPAA, PCI-DSS regulations
- **Company**: (Your company/personal name)
- **Industry**: Technology / Compliance

## Step 4: Wait for Approval

- **Approval time**: Usually 2-5 minutes (can take up to 15 minutes)
- **Status**: Check the "Access granted" status turns green

## Step 5: Verify Access

After approval, run:
```cmd
cd /d "C:\Users\prajw\OneDrive\Desktop\amazon ai\compliance-guardian-ai"
venv\Scripts\python.exe test_bedrock.py
```

## Alternative: Test Without Bedrock

If you want to test the system without Bedrock first, you can:
1. Modify Lambda functions to use mock responses
2. Test the infrastructure and data flow
3. Enable Bedrock later for AI features

---

## Direct Link
https://us-east-1.console.aws.amazon.com/bedrock/home?region=us-east-1#/modelaccess
