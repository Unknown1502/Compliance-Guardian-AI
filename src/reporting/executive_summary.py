"""Executive summary generator for business stakeholders."""

from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from pathlib import Path

from ..utils.logger import get_logger
from ..core.bedrock_client import BedrockClient

logger = get_logger(__name__)


class ExecutiveSummaryGenerator:
    """
    Generate executive-friendly compliance summaries.
    
    Focuses on:
    - Business impact
    - Risk exposure
    - Financial implications
    - Strategic recommendations
    - High-level metrics
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize executive summary generator."""
        self.config = config or {}
        self.bedrock_client = BedrockClient(config)
        self.output_dir = Path(self.config.get("output_dir", "./executive_reports"))
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    async def generate_executive_summary(
        self,
        compliance_data: Dict[str, Any],
        timeframe: str = "monthly"
    ) -> str:
        """Generate executive summary report."""
        try:
            logger.info(f"Generating executive summary for {timeframe}")
            
            # Prepare summary data
            summary = {
                "metadata": {
                    "report_type": f"{timeframe.title()} Executive Compliance Summary",
                    "generated_at": datetime.utcnow().isoformat(),
                    "period": self._get_period_description(timeframe),
                    "prepared_for": "Executive Leadership"
                },
                "executive_overview": await self._generate_overview(compliance_data),
                "key_metrics": self._extract_key_metrics(compliance_data),
                "business_impact": await self._assess_business_impact(compliance_data),
                "risk_exposure": self._analyze_risk_exposure(compliance_data),
                "financial_implications": self._calculate_financial_impact(compliance_data),
                "strategic_recommendations": await self._generate_recommendations(compliance_data),
                "action_items": self._prioritize_actions(compliance_data),
                "comparative_analysis": self._compare_to_previous_period(compliance_data)
            }
            
            # Generate report
            report_path = await self._generate_summary_document(summary)
            
            logger.info(f"Executive summary generated: {report_path}")
            
            return report_path
        
        except Exception as e:
            logger.error(f"Failed to generate executive summary: {e}")
            raise
    
    def _get_period_description(self, timeframe: str) -> str:
        """Get human-readable period description."""
        now = datetime.utcnow()
        
        if timeframe == "weekly":
            start = now - timedelta(days=7)
            return f"{start.strftime('%B %d')} - {now.strftime('%B %d, %Y')}"
        elif timeframe == "monthly":
            return now.strftime("%B %Y")
        elif timeframe == "quarterly":
            quarter = (now.month - 1) // 3 + 1
            return f"Q{quarter} {now.year}"
        elif timeframe == "annual":
            return str(now.year)
        else:
            return "Current Period"
    
    async def _generate_overview(self, data: Dict[str, Any]) -> str:
        """Generate natural language executive overview."""
        violations = data.get("violations", [])
        compliance_score = data.get("compliance_score", 0)
        
        prompt = f"""
        Generate a concise executive summary (3-4 sentences) of the compliance status:
        
        - Overall Compliance Score: {compliance_score}%
        - Total Violations: {len(violations)}
        - Critical Violations: {len([v for v in violations if v.get('severity') == 'critical'])}
        - Frameworks: {', '.join(set(v.get('framework', '') for v in violations))}
        
        Focus on:
        - Overall compliance health
        - Key concerns for leadership
        - Positive trends or areas of improvement
        
        Use business language, not technical jargon.
        """
        
        try:
            response = await self.bedrock_client.invoke_agent(
                agent_id="compliance_agent",
                prompt=prompt
            )
            
            return response.get("completion", "Compliance assessment in progress.")
        
        except Exception as e:
            logger.warning(f"Failed to generate LLM overview: {e}")
            return f"Compliance score at {compliance_score}% with {len(violations)} violations requiring attention."
    
    def _extract_key_metrics(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract key executive metrics."""
        violations = data.get("violations", [])
        
        return {
            "compliance_score": {
                "current": data.get("compliance_score", 0),
                "target": 90,
                "trend": data.get("trend", "stable"),
                "change_percentage": data.get("score_change", 0)
            },
            "risk_status": {
                "overall_risk_level": data.get("risk_level", "medium"),
                "critical_risks": len([v for v in violations if v.get("severity") == "critical"]),
                "high_risks": len([v for v in violations if v.get("severity") == "high"])
            },
            "operational_metrics": {
                "total_violations": len(violations),
                "violations_remediated": data.get("remediated_count", 0),
                "remediation_rate": data.get("remediation_rate", 0),
                "mean_time_to_remediate_hours": data.get("mtr", 0)
            },
            "regulatory_status": {
                "frameworks_assessed": len(set(v.get("framework", "") for v in violations)),
                "frameworks_compliant": data.get("compliant_frameworks", 0),
                "pending_regulatory_submissions": data.get("pending_submissions", 0)
            }
        }
    
    async def _assess_business_impact(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Assess business impact of compliance status."""
        violations = data.get("violations", [])
        
        # Calculate impacts
        reputation_risk = self._assess_reputation_risk(violations)
        operational_impact = self._assess_operational_impact(violations)
        customer_impact = self._assess_customer_impact(violations)
        
        impact_summary = await self._generate_impact_narrative(
            reputation_risk,
            operational_impact,
            customer_impact
        )
        
        return {
            "summary": impact_summary,
            "reputation_risk": reputation_risk,
            "operational_impact": operational_impact,
            "customer_impact": customer_impact,
            "market_position": data.get("market_impact", "neutral")
        }
    
    def _assess_reputation_risk(self, violations: List[Dict[str, Any]]) -> str:
        """Assess reputation risk."""
        critical_public = len([
            v for v in violations
            if v.get("severity") == "critical" and v.get("public_disclosure_required")
        ])
        
        if critical_public > 0:
            return "high"
        elif len([v for v in violations if v.get("severity") in ["critical", "high"]]) > 10:
            return "medium"
        else:
            return "low"
    
    def _assess_operational_impact(self, violations: List[Dict[str, Any]]) -> str:
        """Assess operational impact."""
        service_disruptions = len([
            v for v in violations
            if v.get("service_disruption", False)
        ])
        
        if service_disruptions > 5:
            return "high"
        elif service_disruptions > 0:
            return "medium"
        else:
            return "low"
    
    def _assess_customer_impact(self, violations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess customer impact."""
        total_affected = sum(v.get("affected_individuals", 0) for v in violations)
        
        return {
            "customers_affected": total_affected,
            "impact_level": "high" if total_affected > 1000 else "medium" if total_affected > 100 else "low",
            "notification_required": total_affected > 0
        }
    
    async def _generate_impact_narrative(
        self,
        reputation: str,
        operational: str,
        customer: Dict[str, Any]
    ) -> str:
        """Generate business impact narrative."""
        prompt = f"""
        Generate a brief business impact statement (2-3 sentences) based on:
        
        - Reputation Risk: {reputation}
        - Operational Impact: {operational}
        - Customers Affected: {customer['customers_affected']}
        
        Frame for executive audience. Focus on business implications.
        """
        
        try:
            response = await self.bedrock_client.invoke_agent(
                agent_id="compliance_agent",
                prompt=prompt
            )
            
            return response.get("completion", "Business impact assessment in progress.")
        
        except Exception as e:
            logger.warning(f"Failed to generate impact narrative: {e}")
            return f"Reputation risk: {reputation}, Operational impact: {operational}"
    
    def _analyze_risk_exposure(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze overall risk exposure."""
        violations = data.get("violations", [])
        
        return {
            "overall_risk_score": data.get("overall_risk_score", 0),
            "risk_distribution": {
                "critical": len([v for v in violations if v.get("severity") == "critical"]),
                "high": len([v for v in violations if v.get("severity") == "high"]),
                "medium": len([v for v in violations if v.get("severity") == "medium"]),
                "low": len([v for v in violations if v.get("severity") == "low"])
            },
            "top_risk_areas": self._identify_top_risks(violations),
            "emerging_risks": data.get("emerging_risks", [])
        }
    
    def _identify_top_risks(self, violations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify top risk areas."""
        # Group by type
        risk_groups = {}
        for v in violations:
            risk_type = v.get("violation_type", "Unknown")
            if risk_type not in risk_groups:
                risk_groups[risk_type] = {
                    "type": risk_type,
                    "count": 0,
                    "max_severity": "low"
                }
            
            risk_groups[risk_type]["count"] += 1
            
            # Update max severity
            current_severity = v.get("severity", "low")
            severity_order = ["low", "medium", "high", "critical"]
            if severity_order.index(current_severity) > severity_order.index(risk_groups[risk_type]["max_severity"]):
                risk_groups[risk_type]["max_severity"] = current_severity
        
        # Sort by count and severity
        top_risks = sorted(
            risk_groups.values(),
            key=lambda x: (x["count"], ["low", "medium", "high", "critical"].index(x["max_severity"])),
            reverse=True
        )
        
        return top_risks[:5]
    
    def _calculate_financial_impact(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate financial implications."""
        violations = data.get("violations", [])
        
        # Estimate costs
        remediation_costs = sum(v.get("estimated_cost", 0) for v in violations)
        potential_fines = self._estimate_regulatory_fines(violations)
        business_loss = self._estimate_business_loss(violations)
        
        return {
            "total_estimated_impact": remediation_costs + potential_fines + business_loss,
            "breakdown": {
                "remediation_costs": remediation_costs,
                "potential_regulatory_fines": potential_fines,
                "estimated_business_loss": business_loss
            },
            "cost_avoidance": data.get("cost_avoidance", 0),
            "roi_on_compliance": self._calculate_compliance_roi(data)
        }
    
    def _estimate_regulatory_fines(self, violations: List[Dict[str, Any]]) -> float:
        """Estimate potential regulatory fines."""
        # Simplified estimation
        fine_estimates = {
            "GDPR": {"critical": 1000000, "high": 500000, "medium": 100000, "low": 10000},
            "HIPAA": {"critical": 500000, "high": 250000, "medium": 50000, "low": 5000},
            "PCI_DSS": {"critical": 250000, "high": 100000, "medium": 25000, "low": 2500}
        }
        
        total = 0
        for v in violations:
            framework = v.get("framework", "")
            severity = v.get("severity", "low")
            
            if framework in fine_estimates:
                total += fine_estimates[framework].get(severity, 0)
        
        return total
    
    def _estimate_business_loss(self, violations: List[Dict[str, Any]]) -> float:
        """Estimate business loss from violations."""
        # Simplified: customer churn, reputation damage
        affected_customers = sum(v.get("affected_individuals", 0) for v in violations)
        
        # Assume $100 per affected customer in potential loss
        return affected_customers * 100
    
    def _calculate_compliance_roi(self, data: Dict[str, Any]) -> float:
        """Calculate ROI on compliance investment."""
        compliance_cost = data.get("compliance_investment", 0)
        avoided_costs = data.get("cost_avoidance", 0)
        
        if compliance_cost > 0:
            return ((avoided_costs - compliance_cost) / compliance_cost) * 100
        
        return 0
    
    async def _generate_recommendations(self, data: Dict[str, Any]) -> List[str]:
        """Generate strategic recommendations."""
        violations = data.get("violations", [])
        compliance_score = data.get("compliance_score", 0)
        
        prompt = f"""
        Based on this compliance status, provide 3-5 strategic recommendations 
        for executive leadership:
        
        - Compliance Score: {compliance_score}%
        - Critical Violations: {len([v for v in violations if v.get('severity') == 'critical'])}
        - Total Violations: {len(violations)}
        
        Focus on:
        - Strategic priorities
        - Resource allocation
        - Risk mitigation
        - Business enablement
        
        Be concise and action-oriented. Use business language.
        """
        
        try:
            response = await self.bedrock_client.invoke_agent(
                agent_id="compliance_agent",
                prompt=prompt
            )
            
            # Parse recommendations
            recommendations_text = response.get("completion", "")
            recommendations = self._parse_list(recommendations_text)
            
            return recommendations[:5]
        
        except Exception as e:
            logger.warning(f"Failed to generate recommendations: {e}")
            return [
                "Increase investment in automated compliance monitoring",
                "Prioritize remediation of critical violations",
                "Enhance security awareness training programs"
            ]
    
    def _parse_list(self, text: str) -> List[str]:
        """Parse list from text."""
        import re
        
        # Try numbered list
        pattern = r'\d+\.\s*(.+?)(?=\n\d+\.|\Z)'
        matches = re.findall(pattern, text, re.DOTALL)
        
        if matches:
            return [m.strip() for m in matches if m.strip()]
        
        # Try bullet points
        pattern = r'[-•]\s*(.+?)(?=\n[-•]|\Z)'
        matches = re.findall(pattern, text, re.DOTALL)
        
        if matches:
            return [m.strip() for m in matches if m.strip()]
        
        # Fallback
        lines = [line.strip() for line in text.split('\n') if line.strip()]
        return lines[:5]
    
    def _prioritize_actions(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Prioritize action items."""
        violations = data.get("violations", [])
        
        # Extract critical actions
        actions = []
        
        # Critical violations
        critical = [v for v in violations if v.get("severity") == "critical"]
        if critical:
            actions.append({
                "priority": "immediate",
                "action": f"Address {len(critical)} critical violations",
                "owner": "CISO",
                "deadline": "72 hours"
            })
        
        # Regulatory deadlines
        overdue = [v for v in violations if v.get("remediation_status") == "overdue"]
        if overdue:
            actions.append({
                "priority": "urgent",
                "action": f"Remediate {len(overdue)} overdue violations",
                "owner": "Compliance Team",
                "deadline": "Immediate"
            })
        
        # Compliance improvement
        if data.get("compliance_score", 0) < 80:
            actions.append({
                "priority": "high",
                "action": "Implement compliance improvement plan",
                "owner": "DPO",
                "deadline": "30 days"
            })
        
        return actions[:5]
    
    def _compare_to_previous_period(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Compare to previous period."""
        return {
            "compliance_score_change": data.get("score_change", 0),
            "violation_count_change": data.get("violation_change", 0),
            "remediation_rate_change": data.get("remediation_change", 0),
            "trend": data.get("trend", "stable"),
            "interpretation": self._interpret_trend(data)
        }
    
    def _interpret_trend(self, data: Dict[str, Any]) -> str:
        """Interpret trend data."""
        score_change = data.get("score_change", 0)
        
        if score_change > 5:
            return "Significant improvement in compliance posture"
        elif score_change > 0:
            return "Modest improvement observed"
        elif score_change < -5:
            return "Compliance posture declining - immediate attention required"
        elif score_change < 0:
            return "Slight decline - monitoring recommended"
        else:
            return "Stable compliance posture maintained"
    
    async def _generate_summary_document(self, summary: Dict[str, Any]) -> str:
        """Generate executive summary document."""
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Executive Compliance Summary</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1000px;
            margin: 0 auto;
            padding: 40px;
            background: #f9f9f9;
        }}
        .header {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0 0 10px 0;
            font-size: 28px;
        }}
        .section {{
            background: white;
            padding: 30px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin: 25px 0;
        }}
        .metric-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 10px;
            text-align: center;
        }}
        .metric-value {{
            font-size: 42px;
            font-weight: bold;
            margin: 10px 0;
        }}
        .metric-label {{
            font-size: 14px;
            opacity: 0.9;
        }}
        .trend-up {{ color: #28a745; }}
        .trend-down {{ color: #dc3545; }}
        .recommendation {{
            background: #f8f9fa;
            padding: 15px;
            margin: 10px 0;
            border-left: 4px solid #667eea;
            border-radius: 4px;
        }}
        .action-item {{
            background: #fff3cd;
            padding: 15px;
            margin: 10px 0;
            border-left: 4px solid #ffc107;
            border-radius: 4px;
        }}
        .priority-immediate {{
            border-left-color: #dc3545;
            background: #f8d7da;
        }}
        .priority-urgent {{
            border-left-color: #fd7e14;
            background: #ffe5d0;
        }}
        h2 {{
            color: #1e3c72;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{summary['metadata']['report_type']}</h1>
        <p>Period: {summary['metadata']['period']}</p>
        <p>Generated: {summary['metadata']['generated_at']}</p>
    </div>
    
    <div class="section">
        <h2>Executive Overview</h2>
        <p style="font-size: 16px; line-height: 1.8;">{summary['executive_overview']}</p>
    </div>
    
    <div class="section">
        <h2>Key Metrics</h2>
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-label">Compliance Score</div>
                <div class="metric-value">{summary['key_metrics']['compliance_score']['current']}%</div>
                <div class="metric-label">Target: {summary['key_metrics']['compliance_score']['target']}%</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Total Violations</div>
                <div class="metric-value">{summary['key_metrics']['operational_metrics']['total_violations']}</div>
                <div class="metric-label">Remediation Rate: {summary['key_metrics']['operational_metrics']['remediation_rate']}%</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Critical Risks</div>
                <div class="metric-value">{summary['key_metrics']['risk_status']['critical_risks']}</div>
                <div class="metric-label">High Risks: {summary['key_metrics']['risk_status']['high_risks']}</div>
            </div>
        </div>
    </div>
    
    <div class="section">
        <h2>Financial Impact</h2>
        <p><strong>Total Estimated Impact:</strong> ${summary['financial_implications']['total_estimated_impact']:,.2f}</p>
        <ul>
            <li>Remediation Costs: ${summary['financial_implications']['breakdown']['remediation_costs']:,.2f}</li>
            <li>Potential Fines: ${summary['financial_implications']['breakdown']['potential_regulatory_fines']:,.2f}</li>
            <li>Business Loss: ${summary['financial_implications']['breakdown']['estimated_business_loss']:,.2f}</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>Strategic Recommendations</h2>
        {''.join(f'<div class="recommendation">{rec}</div>' for rec in summary['strategic_recommendations'])}
    </div>
    
    <div class="section">
        <h2>Priority Action Items</h2>
        {''.join(f'''<div class="action-item priority-{action['priority']}">
            <strong>{action['action']}</strong><br>
            Owner: {action['owner']} | Deadline: {action['deadline']}
        </div>''' for action in summary['action_items'])}
    </div>
    
    <div class="section">
        <h2>Period-over-Period Comparison</h2>
        <p><strong>Trend:</strong> {summary['comparative_analysis']['trend'].title()}</p>
        <p>{summary['comparative_analysis']['interpretation']}</p>
    </div>
</body>
</html>
        """
        
        # Save document
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"executive_summary_{timestamp}.html"
        filepath = self.output_dir / filename
        
        filepath.write_text(html_content)
        
        # Also save JSON
        json_path = self.output_dir / f"executive_summary_{timestamp}.json"
        import json
        with open(json_path, 'w') as f:
            json.dump(summary, f, indent=2, default=str)
        
        return str(filepath)
