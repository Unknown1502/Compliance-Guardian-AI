"""
Example: Using the REST API

This example shows how to interact with the Compliance Guardian API.
"""

import requests
import json
from time import sleep


# API Base URL
BASE_URL = "http://localhost:8000/api/v1"


def check_health():
    """Check API health."""
    response = requests.get(f"{BASE_URL}/health")
    print("Health Check:")
    print(json.dumps(response.json(), indent=2))
    print()


def trigger_scan():
    """Trigger a compliance scan."""
    scan_request = {
        "scope": ["GDPR", "HIPAA"],
        "target": {
            "type": "code_repository",
            "url": "https://github.com/example/repo",
            "branch": "main"
        },
        "priority": "high"
    }
    
    response = requests.post(
        f"{BASE_URL}/scans",
        json=scan_request
    )
    
    print("Scan Triggered:")
    print(json.dumps(response.json(), indent=2))
    print()
    
    return response.json().get("scan_id")


def get_scan_status(scan_id):
    """Get scan status."""
    response = requests.get(f"{BASE_URL}/scans/{scan_id}")
    
    print(f"Scan Status (ID: {scan_id}):")
    print(json.dumps(response.json(), indent=2))
    print()
    
    return response.json()


def get_dashboard():
    """Get compliance dashboard."""
    response = requests.get(
        f"{BASE_URL}/reports/dashboard",
        params={"timeframe": "7d"}
    )
    
    print("Compliance Dashboard:")
    dashboard = response.json()
    print(f"Overall Score: {dashboard['overview']['compliance_score']}%")
    print(f"Total Violations: {dashboard['overview']['total_violations']}")
    print(f"Critical: {dashboard['overview']['critical_violations']}")
    print()


def generate_audit_report():
    """Generate an audit report."""
    report_request = {
        "format": "html",
        "include_evidence": True,
        "frameworks": ["GDPR", "HIPAA"]
    }
    
    response = requests.post(
        f"{BASE_URL}/reports/audit",
        json=report_request
    )
    
    print("Audit Report Generated:")
    print(json.dumps(response.json(), indent=2))
    print()


def main():
    """Run API examples."""
    
    print("=" * 60)
    print("Compliance Guardian AI - API Examples")
    print("=" * 60)
    print()
    
    try:
        # 1. Check health
        print("1. Checking API health...")
        check_health()
        
        # 2. Trigger scan
        print("2. Triggering compliance scan...")
        scan_id = trigger_scan()
        
        # 3. Wait a moment
        print("3. Waiting for scan to process...")
        sleep(2)
        
        # 4. Check scan status
        print("4. Checking scan status...")
        scan_result = get_scan_status(scan_id)
        
        # 5. Get dashboard
        print("5. Fetching compliance dashboard...")
        get_dashboard()
        
        # 6. Generate report
        print("6. Generating audit report...")
        generate_audit_report()
        
        print("=" * 60)
        print("All API examples completed successfully!")
        print("=" * 60)
        
    except requests.exceptions.ConnectionError:
        print("ERROR: Cannot connect to API.")
        print("Please ensure the API server is running:")
        print("  python -m src.api.main")
        print()
    except Exception as e:
        print(f"ERROR: {e}")


if __name__ == "__main__":
    main()
