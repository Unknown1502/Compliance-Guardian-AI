"""Example usage of Amazon Q client for compliance intelligence.

This example demonstrates how to use the Amazon Q client to:
1. Query compliance guidance
2. Get policy interpretations
3. Check specific requirements
4. Get remediation guidance
"""

import os
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.amazon_q import AmazonQClient, AmazonQConfig, query_compliance


def example_basic_query():
    """Example 1: Basic compliance query."""
    print("\n=== Example 1: Basic Compliance Query ===")
    
    # Option 1: Use convenience function (uses env vars + mock mode)
    response = query_compliance(
        query="What are the key requirements for GDPR data encryption?",
        framework="GDPR",
        mock=True  # Set to False for production
    )
    
    print(f"Query ID: {response.query_id}")
    print(f"Confidence: {response.confidence_score:.2f}")
    print(f"\nGuidance:\n{response.get_guidance()}")
    print(f"\nSources: {', '.join(response.sources)}")


def example_with_client():
    """Example 2: Using client instance for multiple queries."""
    print("\n=== Example 2: Using Client Instance ===")
    
    # Create client with explicit config
    config = AmazonQConfig(
        application_id=os.getenv("AMAZON_Q_APPLICATION_ID", "test-app"),
        region="us-east-1",
        enable_mock=True  # Set to False for production
    )
    
    client = AmazonQClient(config)
    
    # Query 1: HIPAA encryption requirements
    response1 = client.query_compliance(
        query="What encryption standards does HIPAA require?",
        framework="HIPAA"
    )
    print(f"\nHIPAA Query:")
    print(f"Top Result: {response1.top_result.get('title', 'N/A')}")
    print(f"Excerpt: {response1.top_result.get('excerpt', 'N/A')[:200]}...")
    
    # Query 2: PCI-DSS cardholder data
    response2 = client.query_compliance(
        query="How should cardholder data be protected?",
        framework="PCI-DSS"
    )
    print(f"\nPCI-DSS Query:")
    print(f"Guidance:\n{response2.get_guidance()[:300]}...")


def example_policy_interpretation():
    """Example 3: Get interpretation of a specific policy."""
    print("\n=== Example 3: Policy Interpretation ===")
    
    config = AmazonQConfig(
        application_id="test-app",
        enable_mock=True
    )
    client = AmazonQClient(config)
    
    policy_text = """
    All customer data must be encrypted at rest using AES-256 encryption.
    Data in transit must use TLS 1.2 or higher. Access to encryption keys
    must be restricted to authorized personnel only.
    """
    
    interpretation = client.get_policy_interpretation(
        policy_text=policy_text,
        framework="GDPR"
    )
    
    print(f"Policy: {policy_text.strip()}")
    print(f"\nGDPR Interpretation:\n{interpretation}")


def example_requirement_check():
    """Example 4: Check a specific compliance requirement."""
    print("\n=== Example 4: Requirement Check ===")
    
    config = AmazonQConfig(
        application_id="test-app",
        enable_mock=True
    )
    client = AmazonQClient(config)
    
    result = client.check_requirement(
        requirement="Implement multi-factor authentication for admin access",
        framework="HIPAA",
        context={
            "resource_type": "web_application",
            "user_count": 500,
            "data_classification": "PHI"
        }
    )
    
    print(f"Requirement: {result['requirement']}")
    print(f"Framework: {result['framework']}")
    print(f"Confidence: {result['confidence']:.2f}")
    print(f"\nGuidance:\n{result['guidance']}")
    print(f"\nSources:")
    for source in result['sources']:
        print(f"  - {source}")


def example_remediation_guidance():
    """Example 5: Get guidance for fixing a violation."""
    print("\n=== Example 5: Remediation Guidance ===")
    
    config = AmazonQConfig(
        application_id="test-app",
        enable_mock=True
    )
    client = AmazonQClient(config)
    
    violations = [
        ("S3 bucket 'customer-data' does not have encryption enabled", "GDPR"),
        ("Database lacks audit logging", "HIPAA"),
        ("API endpoint transmits data over HTTP", "PCI-DSS")
    ]
    
    for violation, framework in violations:
        guidance = client.get_remediation_guidance(
            violation=violation,
            framework=framework
        )
        print(f"\nViolation ({framework}): {violation}")
        print(f"Remediation:\n{guidance[:200]}...")


def example_health_check():
    """Example 6: Check client health status."""
    print("\n=== Example 6: Health Check ===")
    
    config = AmazonQConfig(
        application_id="test-app",
        enable_mock=True
    )
    client = AmazonQClient(config)
    
    health = client.health_check()
    
    print(f"Status: {health['status']}")
    print(f"Mode: {health['mode']}")
    print(f"Timestamp: {health['timestamp']}")
    
    if health['status'] == 'healthy':
        print("✓ Amazon Q client is ready")
    else:
        print(f"✗ Error: {health.get('error', 'Unknown')}")


def example_production_setup():
    """Example 7: Production setup with environment variables."""
    print("\n=== Example 7: Production Setup ===")
    
    print("""
To use Amazon Q in production, set these environment variables:

Windows (cmd.exe):
  set AMAZON_Q_APPLICATION_ID=your-app-id-here
  set AWS_REGION=us-east-1
  set AMAZON_Q_INDEX_ID=your-index-id  (optional)
  set AMAZON_Q_MOCK=false

Windows (PowerShell):
  $env:AMAZON_Q_APPLICATION_ID="your-app-id-here"
  $env:AWS_REGION="us-east-1"
  $env:AMAZON_Q_INDEX_ID="your-index-id"  # optional
  $env:AMAZON_Q_MOCK="false"

Linux/Mac:
  export AMAZON_Q_APPLICATION_ID=your-app-id-here
  export AWS_REGION=us-east-1
  export AMAZON_Q_INDEX_ID=your-index-id  # optional
  export AMAZON_Q_MOCK=false

Or create a .env file:
  AMAZON_Q_APPLICATION_ID=your-app-id-here
  AWS_REGION=us-east-1
  AMAZON_Q_MOCK=false

Then use:
  from src.amazon_q import AmazonQClient, AmazonQConfig
  
  # Load from environment
  config = AmazonQConfig.from_env()
  client = AmazonQClient(config)
  
  # Query compliance
  response = client.query_compliance(
      query="Your compliance question",
      framework="GDPR"
  )
    """)


def main():
    """Run all examples."""
    print("=" * 70)
    print("Amazon Q Client Examples for Compliance Guardian AI")
    print("=" * 70)
    
    try:
        example_basic_query()
        example_with_client()
        example_policy_interpretation()
        example_requirement_check()
        example_remediation_guidance()
        example_health_check()
        example_production_setup()
        
        print("\n" + "=" * 70)
        print("All examples completed successfully!")
        print("=" * 70)
        
    except Exception as e:
        print(f"\n✗ Error running examples: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
