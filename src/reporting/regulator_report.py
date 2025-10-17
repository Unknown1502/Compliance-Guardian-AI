"""Regulator-specific report generator."""

from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path
import json

from ..utils.logger import get_logger

logger = get_logger(__name__)


class RegulatorReportGenerator:
    """
    Generate framework-specific reports for regulatory submissions.
    
    Supports:
    - GDPR Article 33 breach notifications
    - HIPAA breach notifications
    - PCI DSS attestations
    - SOX compliance reports
    - Custom regulatory formats
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize regulator report generator."""
        self.config = config or {}
        self.output_dir = Path(self.config.get("output_dir", "./regulatory_reports"))
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    async def generate_gdpr_breach_notification(
        self,
        breach_data: Dict[str, Any]
    ) -> str:
        """Generate GDPR Article 33 breach notification."""
        try:
            logger.info("Generating GDPR breach notification")
            
            notification = {
                "header": {
                    "title": "Personal Data Breach Notification - Article 33 GDPR",
                    "authority": breach_data.get("supervisory_authority", ""),
                    "notification_date": datetime.utcnow().isoformat(),
                    "organization": breach_data.get("organization", {}),
                    "dpo_contact": breach_data.get("dpo_contact", {})
                },
                "breach_details": {
                    "nature_of_breach": breach_data.get("nature", ""),
                    "discovery_date": breach_data.get("discovery_date", ""),
                    "notification_reason": breach_data.get("reason", ""),
                    "categories_of_data": breach_data.get("data_categories", []),
                    "approximate_individuals_affected": breach_data.get("individuals_affected", 0),
                    "approximate_records_affected": breach_data.get("records_affected", 0)
                },
                "likely_consequences": {
                    "description": breach_data.get("consequences", ""),
                    "risk_assessment": breach_data.get("risk_level", ""),
                    "potential_harm": breach_data.get("potential_harm", [])
                },
                "measures_taken": {
                    "containment_actions": breach_data.get("containment", []),
                    "mitigation_measures": breach_data.get("mitigation", []),
                    "notification_to_individuals": breach_data.get("individual_notification", False),
                    "notification_date_individuals": breach_data.get("individual_notification_date", "")
                },
                "contact_point": breach_data.get("contact_point", {}),
                "additional_information": breach_data.get("additional_info", "")
            }
            
            # Generate formal document
            report_path = await self._generate_gdpr_document(notification)
            
            logger.info(f"GDPR breach notification generated: {report_path}")
            
            return report_path
        
        except Exception as e:
            logger.error(f"Failed to generate GDPR notification: {e}")
            raise
    
    async def _generate_gdpr_document(self, notification: Dict[str, Any]) -> str:
        """Generate formal GDPR notification document."""
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>GDPR Breach Notification - Article 33</title>
    <style>
        body {{
            font-family: 'Times New Roman', serif;
            line-height: 1.6;
            max-width: 800px;
            margin: 0 auto;
            padding: 40px;
            color: #000;
        }}
        .header {{
            text-align: center;
            border-bottom: 2px solid #000;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            font-size: 18px;
            margin: 10px 0;
        }}
        .section {{
            margin: 30px 0;
        }}
        .section-title {{
            font-weight: bold;
            font-size: 14px;
            margin-bottom: 10px;
            text-decoration: underline;
        }}
        .field {{
            margin: 10px 0;
        }}
        .field-label {{
            font-weight: bold;
            display: inline-block;
            width: 250px;
        }}
        .signature {{
            margin-top: 60px;
        }}
        ul {{
            margin: 10px 0;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>PERSONAL DATA BREACH NOTIFICATION</h1>
        <h1>Article 33 GDPR</h1>
        <p>To: {notification['header']['authority']}</p>
        <p>Date: {notification['header']['notification_date']}</p>
    </div>
    
    <div class="section">
        <div class="section-title">1. IDENTITY AND CONTACT DETAILS OF CONTROLLER</div>
        <div class="field">
            <span class="field-label">Organization Name:</span>
            {notification['header']['organization'].get('name', 'N/A')}
        </div>
        <div class="field">
            <span class="field-label">Address:</span>
            {notification['header']['organization'].get('address', 'N/A')}
        </div>
        <div class="field">
            <span class="field-label">Contact Email:</span>
            {notification['header']['organization'].get('email', 'N/A')}
        </div>
        <div class="field">
            <span class="field-label">Contact Phone:</span>
            {notification['header']['organization'].get('phone', 'N/A')}
        </div>
    </div>
    
    <div class="section">
        <div class="section-title">2. DATA PROTECTION OFFICER CONTACT</div>
        <div class="field">
            <span class="field-label">DPO Name:</span>
            {notification['header']['dpo_contact'].get('name', 'N/A')}
        </div>
        <div class="field">
            <span class="field-label">DPO Email:</span>
            {notification['header']['dpo_contact'].get('email', 'N/A')}
        </div>
        <div class="field">
            <span class="field-label">DPO Phone:</span>
            {notification['header']['dpo_contact'].get('phone', 'N/A')}
        </div>
    </div>
    
    <div class="section">
        <div class="section-title">3. NATURE OF THE PERSONAL DATA BREACH</div>
        <div class="field">
            <span class="field-label">Description:</span>
            {notification['breach_details']['nature_of_breach']}
        </div>
        <div class="field">
            <span class="field-label">Discovery Date:</span>
            {notification['breach_details']['discovery_date']}
        </div>
        <div class="field">
            <span class="field-label">Categories of Data Affected:</span>
            <ul>
                {''.join(f'<li>{cat}</li>' for cat in notification['breach_details']['categories_of_data'])}
            </ul>
        </div>
        <div class="field">
            <span class="field-label">Approximate Number of Data Subjects:</span>
            {notification['breach_details']['approximate_individuals_affected']}
        </div>
        <div class="field">
            <span class="field-label">Approximate Number of Records:</span>
            {notification['breach_details']['approximate_records_affected']}
        </div>
    </div>
    
    <div class="section">
        <div class="section-title">4. LIKELY CONSEQUENCES OF THE BREACH</div>
        <div class="field">
            <span class="field-label">Risk Assessment:</span>
            {notification['likely_consequences']['risk_assessment']}
        </div>
        <div class="field">
            <span class="field-label">Description of Consequences:</span>
            {notification['likely_consequences']['description']}
        </div>
        <div class="field">
            <span class="field-label">Potential Harm:</span>
            <ul>
                {''.join(f'<li>{harm}</li>' for harm in notification['likely_consequences']['potential_harm'])}
            </ul>
        </div>
    </div>
    
    <div class="section">
        <div class="section-title">5. MEASURES TAKEN OR PROPOSED</div>
        <div class="field">
            <span class="field-label">Containment Actions:</span>
            <ul>
                {''.join(f'<li>{action}</li>' for action in notification['measures_taken']['containment_actions'])}
            </ul>
        </div>
        <div class="field">
            <span class="field-label">Mitigation Measures:</span>
            <ul>
                {''.join(f'<li>{measure}</li>' for measure in notification['measures_taken']['mitigation_measures'])}
            </ul>
        </div>
        <div class="field">
            <span class="field-label">Notification to Data Subjects:</span>
            {'Yes' if notification['measures_taken']['notification_to_individuals'] else 'No'}
        </div>
        {f'''<div class="field">
            <span class="field-label">Date of Notification:</span>
            {notification['measures_taken']['notification_date_individuals']}
        </div>''' if notification['measures_taken']['notification_to_individuals'] else ''}
    </div>
    
    <div class="section">
        <div class="section-title">6. CONTACT POINT</div>
        <div class="field">
            <span class="field-label">Name:</span>
            {notification['contact_point'].get('name', 'N/A')}
        </div>
        <div class="field">
            <span class="field-label">Email:</span>
            {notification['contact_point'].get('email', 'N/A')}
        </div>
        <div class="field">
            <span class="field-label">Phone:</span>
            {notification['contact_point'].get('phone', 'N/A')}
        </div>
    </div>
    
    <div class="section">
        <div class="section-title">7. ADDITIONAL INFORMATION</div>
        <p>{notification['additional_information']}</p>
    </div>
    
    <div class="signature">
        <p>Signature: _________________________</p>
        <p>Name: {notification['header']['dpo_contact'].get('name', 'N/A')}</p>
        <p>Title: Data Protection Officer</p>
        <p>Date: {datetime.utcnow().strftime('%Y-%m-%d')}</p>
    </div>
</body>
</html>
        """
        
        # Save document
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"gdpr_breach_notification_{timestamp}.html"
        filepath = self.output_dir / filename
        
        filepath.write_text(html_content)
        
        # Also save JSON version
        json_path = self.output_dir / f"gdpr_breach_notification_{timestamp}.json"
        with open(json_path, 'w') as f:
            json.dump(notification, f, indent=2, default=str)
        
        return str(filepath)
    
    async def generate_hipaa_breach_notification(
        self,
        breach_data: Dict[str, Any]
    ) -> str:
        """Generate HIPAA breach notification."""
        try:
            logger.info("Generating HIPAA breach notification")
            
            notification = {
                "covered_entity": breach_data.get("covered_entity", {}),
                "breach_details": {
                    "discovery_date": breach_data.get("discovery_date", ""),
                    "breach_occurred": breach_data.get("breach_date", ""),
                    "type_of_breach": breach_data.get("breach_type", ""),
                    "location": breach_data.get("location", ""),
                    "individuals_affected": breach_data.get("individuals_affected", 0),
                    "phi_involved": breach_data.get("phi_categories", [])
                },
                "safeguards": {
                    "in_place": breach_data.get("safeguards_in_place", []),
                    "failed": breach_data.get("safeguards_failed", [])
                },
                "mitigation": {
                    "actions_taken": breach_data.get("actions_taken", []),
                    "sanctions": breach_data.get("sanctions", [])
                },
                "business_associates": breach_data.get("business_associates_involved", []),
                "reported_to_hhs": breach_data.get("hhs_notification_date", ""),
                "media_notice": breach_data.get("media_notice_required", False)
            }
            
            # Generate report
            report_path = await self._generate_hipaa_document(notification)
            
            logger.info(f"HIPAA breach notification generated: {report_path}")
            
            return report_path
        
        except Exception as e:
            logger.error(f"Failed to generate HIPAA notification: {e}")
            raise
    
    async def _generate_hipaa_document(self, notification: Dict[str, Any]) -> str:
        """Generate HIPAA breach notification document."""
        # Create structured JSON report (simplified - in production would be full HHS form)
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"hipaa_breach_notification_{timestamp}.json"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(notification, f, indent=2, default=str)
        
        return str(filepath)
    
    async def generate_pci_attestation(
        self,
        attestation_data: Dict[str, Any]
    ) -> str:
        """Generate PCI DSS Attestation of Compliance (AOC)."""
        try:
            logger.info("Generating PCI DSS AOC")
            
            aoc = {
                "merchant_information": attestation_data.get("merchant_info", {}),
                "assessment_period": {
                    "start": attestation_data.get("period_start", ""),
                    "end": attestation_data.get("period_end", "")
                },
                "merchant_level": attestation_data.get("merchant_level", ""),
                "compliance_status": attestation_data.get("compliance_status", ""),
                "requirements": {
                    "requirement_1": attestation_data.get("req_1_status", False),
                    "requirement_2": attestation_data.get("req_2_status", False),
                    "requirement_3": attestation_data.get("req_3_status", False),
                    "requirement_4": attestation_data.get("req_4_status", False),
                    "requirement_5": attestation_data.get("req_5_status", False),
                    "requirement_6": attestation_data.get("req_6_status", False),
                    "requirement_7": attestation_data.get("req_7_status", False),
                    "requirement_8": attestation_data.get("req_8_status", False),
                    "requirement_9": attestation_data.get("req_9_status", False),
                    "requirement_10": attestation_data.get("req_10_status", False),
                    "requirement_11": attestation_data.get("req_11_status", False),
                    "requirement_12": attestation_data.get("req_12_status", False)
                },
                "non_compliant_requirements": attestation_data.get("non_compliant", []),
                "remediation_plan": attestation_data.get("remediation_plan", []),
                "qsa_information": attestation_data.get("qsa_info", {}),
                "executive_signature": attestation_data.get("signature", {})
            }
            
            # Generate document
            report_path = await self._generate_pci_document(aoc)
            
            logger.info(f"PCI DSS AOC generated: {report_path}")
            
            return report_path
        
        except Exception as e:
            logger.error(f"Failed to generate PCI AOC: {e}")
            raise
    
    async def _generate_pci_document(self, aoc: Dict[str, Any]) -> str:
        """Generate PCI DSS AOC document."""
        # Save as JSON (in production, would use official PCI AOC template)
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"pci_aoc_{timestamp}.json"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(aoc, f, indent=2, default=str)
        
        return str(filepath)
    
    async def generate_sox_compliance_report(
        self,
        sox_data: Dict[str, Any]
    ) -> str:
        """Generate SOX compliance report."""
        try:
            logger.info("Generating SOX compliance report")
            
            report = {
                "company_information": sox_data.get("company_info", {}),
                "reporting_period": {
                    "fiscal_year": sox_data.get("fiscal_year", ""),
                    "quarter": sox_data.get("quarter", "")
                },
                "internal_controls": {
                    "design_effectiveness": sox_data.get("design_effectiveness", ""),
                    "operating_effectiveness": sox_data.get("operating_effectiveness", ""),
                    "material_weaknesses": sox_data.get("material_weaknesses", []),
                    "significant_deficiencies": sox_data.get("significant_deficiencies", [])
                },
                "it_general_controls": {
                    "access_controls": sox_data.get("access_controls_status", ""),
                    "change_management": sox_data.get("change_mgmt_status", ""),
                    "backup_recovery": sox_data.get("backup_recovery_status", ""),
                    "computer_operations": sox_data.get("operations_status", "")
                },
                "testing_results": sox_data.get("testing_results", []),
                "remediation_plans": sox_data.get("remediation_plans", []),
                "management_assertion": sox_data.get("management_assertion", ""),
                "auditor_opinion": sox_data.get("auditor_opinion", {})
            }
            
            # Generate document
            report_path = await self._generate_sox_document(report)
            
            logger.info(f"SOX compliance report generated: {report_path}")
            
            return report_path
        
        except Exception as e:
            logger.error(f"Failed to generate SOX report: {e}")
            raise
    
    async def _generate_sox_document(self, report: Dict[str, Any]) -> str:
        """Generate SOX compliance report document."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"sox_compliance_report_{timestamp}.json"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        return str(filepath)
    
    async def generate_custom_regulatory_report(
        self,
        framework: str,
        report_data: Dict[str, Any],
        template: Optional[str] = None
    ) -> str:
        """Generate custom regulatory report."""
        try:
            logger.info(f"Generating custom {framework} report")
            
            # Use template if provided, otherwise create generic report
            if template:
                report_path = await self._apply_template(template, report_data)
            else:
                report_path = await self._generate_generic_report(framework, report_data)
            
            logger.info(f"Custom report generated: {report_path}")
            
            return report_path
        
        except Exception as e:
            logger.error(f"Failed to generate custom report: {e}")
            raise
    
    async def _generate_generic_report(
        self,
        framework: str,
        data: Dict[str, Any]
    ) -> str:
        """Generate generic regulatory report."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"{framework.lower()}_report_{timestamp}.json"
        filepath = self.output_dir / filename
        
        report = {
            "framework": framework,
            "generated_at": datetime.utcnow().isoformat(),
            "data": data
        }
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        return str(filepath)
    
    async def _apply_template(self, template: str, data: Dict[str, Any]) -> str:
        """Apply template to generate report."""
        # Template processing (simplified)
        # In production, use templating engine like Jinja2
        
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"custom_report_{timestamp}.html"
        filepath = self.output_dir / filename
        
        # Simple template substitution
        content = template
        for key, value in data.items():
            content = content.replace(f"{{{{{key}}}}}", str(value))
        
        filepath.write_text(content)
        
        return str(filepath)
