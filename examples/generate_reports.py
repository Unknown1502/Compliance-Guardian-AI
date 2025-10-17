"""
Example: Generate Compliance Reports

This example demonstrates generating compliance reports from scan results.
"""

import requests
import json
import os
from datetime import datetime


def main():
    """Generate compliance reports from API scans."""
    
    # API endpoint
    API_ENDPOINT = "https://gluwdyp4ii.execute-api.us-east-1.amazonaws.com/production/scan"
    
    print("=" * 70)
    print("[LAUNCH] COMPLIANCE GUARDIAN AI - REPORT GENERATION EXAMPLE")
    print("=" * 70)
    
    # Perform scans for multiple frameworks
    frameworks = ["GDPR", "HIPAA", "PCI_DSS"]
    scan_results = []
    
    print("\n[STEP 1] Running compliance scans across multiple frameworks...")
    print("-" * 70)
    
    for framework in frameworks:
        print(f"\n[SCANNING] {framework}...")
        
        scan_request = {
            "scan_type": framework,
            "target": "enterprise-application",
            "scope": ["data_protection", "encryption", "access_controls", "audit_logging"]
        }
        
        try:
            response = requests.post(
                API_ENDPOINT,
                json=scan_request,
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                scan_results.append({
                    "framework": framework,
                    "scan_id": result.get('scan_id'),
                    "status": result.get('status'),
                    "timestamp": result.get('timestamp'),
                    "violations_found": result.get('violations_found', 0),
                    "analysis": result.get('analysis', ''),
                    "recommendations": result.get('recommendations', [])
                })
                print(f"  [OK] {framework} scan completed - {result.get('scan_id')}")
                print(f"  [RESULT] Violations: {result.get('violations_found', 0)}")
            else:
                print(f"  [ERROR] {framework} scan failed: {response.status_code}")
                
        except Exception as e:
            print(f"  [ERROR] {framework} scan error: {str(e)}")
    
    # Generate comprehensive report
    print("\n" + "=" * 70)
    print("[STEP 2] GENERATING COMPREHENSIVE COMPLIANCE REPORT")
    print("=" * 70)
    
    # Generate comprehensive report
    print("\n" + "=" * 70)
    print("[STEP 2] GENERATING COMPREHENSIVE COMPLIANCE REPORT")
    print("=" * 70)
    
    if scan_results:
        # Report Header
        print(f"\n[REPORT] Compliance Guardian AI - Multi-Framework Analysis")
        print(f"[REPORT] Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[REPORT] Target: enterprise-application")
        print(f"[REPORT] Frameworks Assessed: {len(scan_results)}")
        print("\n" + "-" * 70)
        
        # Framework-by-Framework Analysis
        total_violations = 0
        for result in scan_results:
            print(f"\n[{result['framework']}] COMPLIANCE ANALYSIS")
            print(f"  Scan ID: {result['scan_id']}")
            print(f"  Status: {result['status']}")
            print(f"  Violations: {result['violations_found']}")
            total_violations += result['violations_found']
            
            # Show key recommendations
            if result['recommendations']:
                print(f"  Key Recommendations:")
                for i, rec in enumerate(result['recommendations'][:3], 1):
                    print(f"    {i}. {rec}")
        
        # Executive Summary
        print("\n" + "=" * 70)
        print("[EXECUTIVE SUMMARY]")
        print("=" * 70)
        print(f"  Total Frameworks Scanned: {len(scan_results)}")
        print(f"  Total Violations Detected: {total_violations}")
        print(f"  Compliance Score: {max(0, 100 - (total_violations * 5))}%")
        print(f"  Risk Level: {'High' if total_violations > 5 else 'Medium' if total_violations > 0 else 'Low'}")
        
        # Recommendations Priority
        print("\n[PRIORITY ACTIONS]")
        all_recommendations = []
        for result in scan_results:
            for rec in result['recommendations']:
                if rec not in all_recommendations:
                    all_recommendations.append(rec)
        
        for i, rec in enumerate(all_recommendations[:5], 1):
            print(f"  {i}. {rec}")
        
        # Compliance Metrics
        print("\n[METRICS]")
        print(f"  Scans Completed: {len(scan_results)}")
        print(f"  AI-Powered Analysis: {len([r for r in scan_results if r['analysis']])} frameworks")
        print(f"  Total Recommendations: {sum(len(r['recommendations']) for r in scan_results)}")
        print(f"  Estimated Remediation Time: {total_violations * 30} minutes")
        print(f"  Potential Cost Savings: ${total_violations * 50000:,} (compliance penalties avoided)")
        
        # Create reports directory if it doesn't exist
        import os
        os.makedirs('reports', exist_ok=True)
        
        # Save report to file
        report_filename = f"reports/compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_filename, 'w') as f:
            json.dump({
                "report_metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "target": "enterprise-application",
                    "frameworks": frameworks
                },
                "scan_results": scan_results,
                "summary": {
                    "total_violations": total_violations,
                    "compliance_score": max(0, 100 - (total_violations * 5)),
                    "risk_level": "high" if total_violations > 5 else "medium" if total_violations > 0 else "low",
                    "recommendations": all_recommendations[:10]
                }
            }, f, indent=2)
        
        print(f"\n[OK] Report saved: {report_filename}")
        print("\n" + "=" * 70)
        print("[OK] REPORT GENERATION COMPLETE!")
        print("=" * 70)
    else:
        print("\n[WARNING] No scan results available to generate report")


if __name__ == "__main__":
    main()

