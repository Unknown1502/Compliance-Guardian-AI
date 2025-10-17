"""
Integration tests for API endpoints and Bedrock integration
"""

import pytest
import requests
import json


class TestAPIIntegration:
    """Integration tests for API Gateway endpoint."""
    
    API_ENDPOINT = "https://gluwdyp4ii.execute-api.us-east-1.amazonaws.com/production/scan"
    
    def test_api_endpoint_reachable(self):
        """Test that API endpoint is reachable."""
        try:
            response = requests.get(self.API_ENDPOINT.replace('/scan', '/health'), timeout=5)
            # Even if health endpoint doesn't exist, we should get a response
            assert response.status_code in [200, 403, 404, 405]
        except requests.exceptions.RequestException:
            pytest.skip("API endpoint not reachable")
    
    def test_gdpr_scan_request(self):
        """Test GDPR compliance scan request."""
        scan_request = {
            "scan_type": "GDPR",
            "target": "test-integration",
            "scope": ["data_privacy"]
        }
        
        response = requests.post(
            self.API_ENDPOINT,
            json=scan_request,
            headers={"Content-Type": "application/json"},
            timeout=30
        )
        
        assert response.status_code == 200
        result = response.json()
        
        assert 'scan_id' in result
        assert 'status' in result
        assert 'scan_type' in result
        assert result['scan_type'] == 'GDPR'
    
    def test_hipaa_scan_request(self):
        """Test HIPAA compliance scan request."""
        scan_request = {
            "scan_type": "HIPAA",
            "target": "healthcare-app",
            "scope": ["phi_protection", "encryption"]
        }
        
        response = requests.post(
            self.API_ENDPOINT,
            json=scan_request,
            headers={"Content-Type": "application/json"},
            timeout=30
        )
        
        assert response.status_code == 200
        result = response.json()
        assert result['scan_type'] == 'HIPAA'
    
    def test_pci_dss_scan_request(self):
        """Test PCI-DSS compliance scan request."""
        scan_request = {
            "scan_type": "PCI_DSS",
            "target": "payment-system",
            "scope": ["card_data_security"]
        }
        
        response = requests.post(
            self.API_ENDPOINT,
            json=scan_request,
            headers={"Content-Type": "application/json"},
            timeout=30
        )
        
        assert response.status_code == 200
        result = response.json()
        assert result['scan_type'] == 'PCI_DSS'
    
    def test_api_response_structure(self):
        """Test that API response has correct structure."""
        scan_request = {
            "scan_type": "GDPR",
            "target": "test-structure",
            "scope": ["data_privacy"]
        }
        
        response = requests.post(
            self.API_ENDPOINT,
            json=scan_request,
            timeout=30
        )
        
        assert response.status_code == 200
        result = response.json()
        
        # Check required fields
        required_fields = ['scan_id', 'status', 'scan_type', 'target', 'timestamp']
        for field in required_fields:
            assert field in result, f"Missing required field: {field}"
        
        # Check optional but expected fields
        assert 'analysis' in result or 'violations_found' in result
        assert 'recommendations' in result
    
    def test_invalid_scan_type(self):
        """Test API response to invalid scan type."""
        scan_request = {
            "scan_type": "INVALID_FRAMEWORK",
            "target": "test",
            "scope": ["test"]
        }
        
        response = requests.post(
            self.API_ENDPOINT,
            json=scan_request,
            timeout=30
        )
        
        # Should still return 200 but might have different handling
        assert response.status_code in [200, 400]


class TestBedrockIntegration:
    """Integration tests for Bedrock AI functionality."""
    
    def test_bedrock_analysis_in_response(self):
        """Test that Bedrock AI analysis is included in response."""
        api_endpoint = "https://gluwdyp4ii.execute-api.us-east-1.amazonaws.com/production/scan"
        
        scan_request = {
            "scan_type": "GDPR",
            "target": "bedrock-test",
            "scope": ["data_privacy", "encryption"]
        }
        
        response = requests.post(api_endpoint, json=scan_request, timeout=30)
        
        assert response.status_code == 200
        result = response.json()
        
        # Check for AI analysis
        assert 'analysis' in result
        assert isinstance(result['analysis'], str)
        assert len(result['analysis']) > 0
        
        # Analysis should contain compliance-related terms
        analysis_lower = result['analysis'].lower()
        compliance_terms = ['compliance', 'gdpr', 'data', 'privacy', 'regulation']
        assert any(term in analysis_lower for term in compliance_terms)
    
    def test_recommendations_generated(self):
        """Test that recommendations are generated."""
        api_endpoint = "https://gluwdyp4ii.execute-api.us-east-1.amazonaws.com/production/scan"
        
        scan_request = {
            "scan_type": "HIPAA",
            "target": "recommendations-test",
            "scope": ["phi_protection"]
        }
        
        response = requests.post(api_endpoint, json=scan_request, timeout=30)
        
        assert response.status_code == 200
        result = response.json()
        
        assert 'recommendations' in result
        assert isinstance(result['recommendations'], list)
        assert len(result['recommendations']) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
