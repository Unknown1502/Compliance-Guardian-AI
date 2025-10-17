"""
Example: Basic Compliance Scan

This example demonstrates how to use the Compliance Guardian AI
to perform a basic compliance scan via the API endpoint.
"""

import requests
import json
from datetime import datetime


def main():
    """Run a basic compliance scan."""
    
    # API endpoint
    API_ENDPOINT = "https://gluwdyp4ii.execute-api.us-east-1.amazonaws.com/production/scan"
    
    # Define scan request
    scan_request = {
        "scan_type": "GDPR",
        "target": "example-repository",
        "scope": ["data_privacy", "encryption", "access_controls"]
    }
    
    print("=" * 60)
    print("[LAUNCH] COMPLIANCE GUARDIAN AI - BASIC SCAN EXAMPLE")
    print("=" * 60)
    print(f"\n[INFO] Target: {scan_request['target']}")
    print(f"[INFO] Framework: {scan_request['scan_type']}")
    print(f"[INFO] Scope: {', '.join(scan_request['scope'])}")
    print("\n[REQUEST] Sending scan request to API...")
    
    try:
        # Send API request
        response = requests.post(
            API_ENDPOINT,
            json=scan_request,
            headers={"Content-Type": "application/json"},
            timeout=30
        )
        
        # Check response
        if response.status_code == 200:
            result = response.json()
            
            print("\n" + "=" * 60)
            print("[OK] SCAN COMPLETED SUCCESSFULLY")
            print("=" * 60)
            
            print(f"\n[RESULT] Scan ID: {result.get('scan_id')}")
            print(f"[RESULT] Status: {result.get('status')}")
            print(f"[RESULT] Timestamp: {result.get('timestamp')}")
            print(f"[RESULT] Violations Found: {result.get('violations_found', 0)}")
            
            # Display AI analysis
            analysis = result.get('analysis', '')
            if analysis:
                print("\n[ANALYSIS] Bedrock AI Analysis:")
                print("-" * 60)
                # Show first 500 characters
                print(analysis[:500] + "..." if len(analysis) > 500 else analysis)
            
            # Display recommendations
            recommendations = result.get('recommendations', [])
            if recommendations:
                print("\n[RECOMMENDATIONS]")
                for i, rec in enumerate(recommendations, 1):
                    print(f"  {i}. {rec}")
            
            print("\n" + "=" * 60)
            print("[OK] SCAN COMPLETE!")
            print("=" * 60)
            
        else:
            print(f"\n[ERROR] API returned status code: {response.status_code}")
            print(f"[ERROR] Response: {response.text}")
            
    except requests.exceptions.RequestException as e:
        print(f"\n[ERROR] Request failed: {str(e)}")
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {str(e)}")


if __name__ == "__main__":
    main()

