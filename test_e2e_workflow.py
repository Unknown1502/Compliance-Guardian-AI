"""
End-to-End Workflow Test
Tests the complete compliance workflow from scan to report generation
"""

import requests
import json
import time
from datetime import datetime


def test_complete_workflow():
    """Test complete compliance workflow end-to-end."""
    
    print("=" * 80)
    print("COMPLIANCE GUARDIAN AI - END-TO-END WORKFLOW TEST")
    print("=" * 80)
    
    # Configuration
    api_endpoint = "https://gluwdyp4ii.execute-api.us-east-1.amazonaws.com/production/scan"
    
    # Step 1: Compliance Scan
    print("\n[STEP 1] Initiating Compliance Scan...")
    print("-" * 80)
    
    scan_request = {
        "scan_type": "GDPR",
        "target": "e2e-test-application",
        "scope": ["data_privacy", "encryption", "access_controls", "audit_logging"]
    }
    
    print(f"Scan Type: {scan_request['scan_type']}")
    print(f"Target: {scan_request['target']}")
    print(f"Scope: {', '.join(scan_request['scope'])}")
    
    try:
        start_time = time.time()
        response = requests.post(
            api_endpoint,
            json=scan_request,
            headers={"Content-Type": "application/json"},
            timeout=30
        )
        scan_duration = time.time() - start_time
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        scan_result = response.json()
        
        print(f"\n[OK] Scan completed in {scan_duration:.2f}s")
        print(f"[RESULT] Scan ID: {scan_result.get('scan_id')}")
        print(f"[RESULT] Status: {scan_result.get('status')}")
        print(f"[RESULT] Timestamp: {scan_result.get('timestamp')}")
        
        # Step 2: Violation Detection (AI Analysis)
        print("\n[STEP 2] Analyzing Violations (AWS Bedrock)...")
        print("-" * 80)
        
        analysis = scan_result.get('analysis', '')
        assert len(analysis) > 0, "No AI analysis returned"
        
        print(f"[OK] Bedrock Analysis Generated ({len(analysis)} characters)")
        print(f"[PREVIEW] {analysis[:200]}...")
        
        # Step 3: Recommendations
        print("\n[STEP 3] Generating Remediation Recommendations...")
        print("-" * 80)
        
        recommendations = scan_result.get('recommendations', [])
        assert len(recommendations) > 0, "No recommendations returned"
        
        print(f"[OK] {len(recommendations)} recommendations generated:")
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")
        
        # Step 4: Report Generation
        print("\n[STEP 4] Generating Compliance Report...")
        print("-" * 80)
        
        report_data = {
            "scan_id": scan_result.get('scan_id'),
            "scan_type": scan_result.get('scan_type'),
            "target": scan_result.get('target'),
            "timestamp": scan_result.get('timestamp'),
            "duration": scan_duration,
            "status": scan_result.get('status'),
            "violations_found": scan_result.get('violations_found', 0),
            "analysis": analysis[:500],  # Truncated for report
            "recommendations": recommendations,
            "test_run": True
        }
        
        report_filename = f"e2e_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_filename, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"[OK] Report saved: {report_filename}")
        
        # Step 5: Workflow Verification
        print("\n[STEP 5] Verifying Complete Workflow...")
        print("-" * 80)
        
        checks = {
            "API Gateway Response": response.status_code == 200,
            "Scan ID Generated": 'scan_id' in scan_result,
            "Bedrock Analysis Received": len(analysis) > 0,
            "Recommendations Generated": len(recommendations) > 0,
            "Report Created": True,  # File was created
            "Response Time < 15s": scan_duration < 15
        }
        
        all_passed = all(checks.values())
        
        for check, passed in checks.items():
            status = "[OK]" if passed else "[FAIL]"
            print(f"  {status} {check}")
        
        # Final Summary
        print("\n" + "=" * 80)
        if all_passed:
            print("[SUCCESS] END-TO-END WORKFLOW COMPLETE!")
        else:
            print("[WARNING] WORKFLOW COMPLETED WITH ISSUES")
        print("=" * 80)
        
        print(f"\nWorkflow Summary:")
        print(f"  Total Duration: {scan_duration:.2f}s")
        print(f"  API Status: {response.status_code}")
        print(f"  Scan ID: {scan_result.get('scan_id')}")
        print(f"  Analysis Length: {len(analysis)} characters")
        print(f"  Recommendations: {len(recommendations)}")
        print(f"  Report File: {report_filename}")
        print(f"  All Checks Passed: {'Yes' if all_passed else 'No'}")
        
        # Test Multiple Frameworks
        print("\n[BONUS] Testing Multi-Framework Support...")
        print("-" * 80)
        
        frameworks = ["HIPAA", "PCI_DSS"]
        for framework in frameworks:
            print(f"\n[TEST] {framework} Framework...")
            test_request = {
                "scan_type": framework,
                "target": f"e2e-test-{framework.lower()}",
                "scope": ["security", "compliance"]
            }
            
            test_response = requests.post(api_endpoint, json=test_request, timeout=30)
            if test_response.status_code == 200:
                result = test_response.json()
                print(f"  [OK] {framework} scan successful: {result.get('scan_id')}")
            else:
                print(f"  [FAIL] {framework} scan failed: {test_response.status_code}")
        
        print("\n" + "=" * 80)
        print("[COMPLETE] END-TO-END WORKFLOW TEST FINISHED")
        print("=" * 80)
        
        return all_passed
        
    except requests.exceptions.RequestException as e:
        print(f"\n[ERROR] API Request failed: {str(e)}")
        return False
    except AssertionError as e:
        print(f"\n[ERROR] Assertion failed: {str(e)}")
        return False
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {str(e)}")
        return False


if __name__ == "__main__":
    success = test_complete_workflow()
    exit(0 if success else 1)
