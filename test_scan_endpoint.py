"""
Quick test of the /scan endpoint
"""

import requests
import json

# Your API Gateway URL
BASE_URL = "https://gluwdyp4ii.execute-api.us-east-1.amazonaws.com/production"

# Test the /scan endpoint
scan_url = f"{BASE_URL}/scan"

# Sample scan payload
scan_data = {
    "scan_type": "GDPR",
    "target": "test-repository",
    "scope": ["data_privacy"]
}

print(f"[TEST] Testing: POST {scan_url}")
print(f"[UPLOAD] Payload: {json.dumps(scan_data, indent=2)}\n")

try:
    response = requests.post(scan_url, json=scan_data, timeout=30)
    
    print(f"[STATS] Status Code: {response.status_code}")
    print(f"[LIST] Response:")
    try:
        print(json.dumps(response.json(), indent=2))
    except:
        print(response.text)
    
    if response.status_code == 200:
        print("\n[OK] API Gateway is working!")
    else:
        print(f"\n[WARNING]  Got status {response.status_code}")
        
except Exception as e:
    print(f"[ERROR] Error: {e}")
