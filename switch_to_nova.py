"""
Update Lambda functions to use Amazon Nova instead of Claude
Nova models don't require approval forms and work immediately
"""
import os
import json

print("=" * 70)
print(" SWITCHING TO AMAZON NOVA MODELS")
print("=" * 70)

print("\n[NOTE] Amazon Nova advantages:")
print("   [OK] No approval form needed")
print("   [OK] Works immediately")
print("   [OK] Lower cost than Claude")
print("   [OK] Fast inference")
print("   [OK] Good for compliance analysis")

print("\n[TOOL] Model Switch:")
print("   FROM: us.anthropic.claude-3-5-sonnet-20241022-v2:0")
print("   TO:   us.amazon.nova-pro-v1:0")

# Read infrastructure config
config_file = 'infrastructure_config.json'
if os.path.exists(config_file):
    with open(config_file, 'r') as f:
        config = json.load(f)
    
    # Update model ID
    config['bedrock_model'] = 'us.amazon.nova-pro-v1:0'
    
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2)
    
    print(f"\n[OK] Updated {config_file}")
else:
    print(f"\n[WARNING]  {config_file} not found, will create new config")
    config = {
        'region': 'us-east-1',
        'environment': 'production',
        'bedrock_model': 'us.amazon.nova-pro-v1:0'
    }
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2)
    print(f"[OK] Created {config_file}")

print("\n[NOTE] NEXT STEP:")
print("   Update Lambda environment variables:")
print("   BEDROCK_MODEL_ID=us.amazon.nova-pro-v1:0")

print("\n[FAST] Quick update command:")
print("   python update_lambda_model.py")

print("\n" + "=" * 70)
