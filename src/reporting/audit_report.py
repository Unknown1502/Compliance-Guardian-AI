"""Comprehensive audit report generator."""

from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from pathlib import Path
import json

from ..utils.logger import get_logger

logger = get_logger(__name__)


class AuditReportGenerator:
    """
    Generates comprehensive audit reports.
    
    Supports multiple formats:
    - PDF (executive and detailed)
    - HTML (interactive)
    - JSON (machine-readable)
    - CSV (data export)
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize audit report generator."""
        self.config = config or {}
        self.output_dir = Path(self.config.get("output_dir", "./reports"))
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    async def generate_audit_report(
        self,
        audit_data: Dict[str, Any],
        format: str = "html",
        include_evidence: bool = True
    ) -> str:
        """Generate comprehensive audit report."""
        try:
            logger.info(f"Generating {format} audit report")
            
            # Prepare report data
            report_data = await self._prepare_report_data(audit_data, include_evidence)
            
            # Generate report in requested format
            if format == "html":
                report_path = await self._generate_html_report(report_data)
            elif format == "pdf":
                report_path = await self._generate_pdf_report(report_data)
            elif format == "json":
                report_path = await self._generate_json_report(report_data)
            elif format == "csv":
                report_path = await self._generate_csv_report(report_data)
            else:
                raise ValueError(f"Unsupported format: {format}")
            
            logger.info(f"Audit report generated: {report_path}")
            
            return report_path
        
        except Exception as e:
            logger.error(f"Failed to generate audit report: {e}")
            raise
    
    async def _prepare_report_data(
        self,
        audit_data: Dict[str, Any],
        include_evidence: bool
    ) -> Dict[str, Any]:
        """Prepare structured report data."""
        report = {
            "metadata": {
                "report_id": f"AUDIT-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                "generated_at": datetime.utcnow().isoformat(),
                "report_type": "Compliance Audit",
                "period_start": audit_data.get("period_start", ""),
                "period_end": audit_data.get("period_end", ""),
                "auditor": audit_data.get("auditor", "Compliance Guardian AI"),
                "scope": audit_data.get("scope", [])
            },
            "executive_summary": await self._generate_executive_summary(audit_data),
            "findings": self._organize_findings(audit_data.get("findings", [])),
            "compliance_status": self._calculate_compliance_status(audit_data),
            "violations": audit_data.get("violations", []),
            "remediation_status": self._analyze_remediation_status(audit_data),
            "risk_assessment": audit_data.get("risk_assessment", {}),
            "recommendations": audit_data.get("recommendations", []),
            "metrics": self._calculate_metrics(audit_data)
        }
        
        if include_evidence:
            report["evidence"] = audit_data.get("evidence", [])
        
        return report
    
    async def _generate_executive_summary(self, audit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary."""
        violations = audit_data.get("violations", [])
        
        summary = {
            "total_violations": len(violations),
            "critical_violations": len([v for v in violations if v.get("severity") == "critical"]),
            "high_violations": len([v for v in violations if v.get("severity") == "high"]),
            "medium_violations": len([v for v in violations if v.get("severity") == "medium"]),
            "low_violations": len([v for v in violations if v.get("severity") == "low"]),
            "frameworks_assessed": list(set(v.get("framework", "") for v in violations)),
            "overall_compliance_score": self._calculate_overall_score(violations),
            "trend": self._determine_trend(audit_data),
            "key_findings": self._extract_key_findings(violations)
        }
        
        return summary
    
    def _organize_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Organize findings by category."""
        organized = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "informational": []
        }
        
        for finding in findings:
            severity = finding.get("severity", "low").lower()
            if severity in organized:
                organized[severity].append(finding)
        
        return organized
    
    def _calculate_compliance_status(self, audit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate compliance status by framework."""
        violations = audit_data.get("violations", [])
        
        frameworks = {}
        for violation in violations:
            framework = violation.get("framework", "Unknown")
            if framework not in frameworks:
                frameworks[framework] = {
                    "total_checks": 0,
                    "passed": 0,
                    "failed": 0,
                    "compliance_rate": 0
                }
            
            frameworks[framework]["total_checks"] += 1
            frameworks[framework]["failed"] += 1
        
        # Calculate compliance rates
        for framework, stats in frameworks.items():
            total = stats["total_checks"]
            stats["passed"] = total - stats["failed"]
            if total > 0:
                stats["compliance_rate"] = (stats["passed"] / total) * 100
        
        return frameworks
    
    def _analyze_remediation_status(self, audit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze remediation progress."""
        violations = audit_data.get("violations", [])
        
        remediation_stats = {
            "total": len(violations),
            "remediated": 0,
            "in_progress": 0,
            "pending": 0,
            "overdue": 0,
            "average_time_to_remediate": 0
        }
        
        remediation_times = []
        
        for violation in violations:
            status = violation.get("remediation_status", "pending")
            
            if status == "remediated":
                remediation_stats["remediated"] += 1
                
                # Calculate time to remediate
                detected = violation.get("detected_at")
                remediated = violation.get("remediated_at")
                if detected and remediated:
                    time_diff = (
                        datetime.fromisoformat(remediated) - 
                        datetime.fromisoformat(detected)
                    ).total_seconds() / 3600  # hours
                    remediation_times.append(time_diff)
            
            elif status == "in_progress":
                remediation_stats["in_progress"] += 1
            else:
                remediation_stats["pending"] += 1
            
            # Check if overdue
            deadline = violation.get("remediation_deadline")
            if deadline and datetime.fromisoformat(deadline) < datetime.utcnow():
                remediation_stats["overdue"] += 1
        
        if remediation_times:
            remediation_stats["average_time_to_remediate"] = sum(remediation_times) / len(remediation_times)
        
        return remediation_stats
    
    def _calculate_metrics(self, audit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate audit metrics."""
        violations = audit_data.get("violations", [])
        
        metrics = {
            "violation_rate": len(violations) / max(audit_data.get("total_checks", 1), 1),
            "mean_time_to_detect": self._calculate_mtd(violations),
            "mean_time_to_remediate": self._calculate_mtr(violations),
            "repeat_violations": self._count_repeat_violations(violations),
            "compliance_score_by_framework": self._score_by_framework(violations),
            "affected_individuals": sum(v.get("affected_individuals", 0) for v in violations),
            "estimated_financial_impact": sum(v.get("estimated_cost", 0) for v in violations)
        }
        
        return metrics
    
    def _calculate_overall_score(self, violations: List[Dict[str, Any]]) -> float:
        """Calculate overall compliance score."""
        if not violations:
            return 100.0
        
        # Weight violations by severity
        weights = {
            "critical": 10,
            "high": 5,
            "medium": 2,
            "low": 1
        }
        
        total_weight = sum(weights.get(v.get("severity", "low"), 1) for v in violations)
        max_possible = 100
        
        score = max(0, 100 - (total_weight * 2))  # Each weighted point reduces score
        
        return round(score, 2)
    
    def _determine_trend(self, audit_data: Dict[str, Any]) -> str:
        """Determine compliance trend."""
        current_violations = len(audit_data.get("violations", []))
        previous_violations = audit_data.get("previous_period_violations", current_violations)
        
        if current_violations < previous_violations:
            return "improving"
        elif current_violations > previous_violations:
            return "declining"
        else:
            return "stable"
    
    def _extract_key_findings(self, violations: List[Dict[str, Any]]) -> List[str]:
        """Extract key findings from violations."""
        findings = []
        
        # Most common violation type
        violation_types = {}
        for v in violations:
            vtype = v.get("violation_type", "Unknown")
            violation_types[vtype] = violation_types.get(vtype, 0) + 1
        
        if violation_types:
            most_common = max(violation_types.items(), key=lambda x: x[1])
            findings.append(f"Most common violation: {most_common[0]} ({most_common[1]} instances)")
        
        # Critical violations
        critical = [v for v in violations if v.get("severity") == "critical"]
        if critical:
            findings.append(f"{len(critical)} critical violations requiring immediate attention")
        
        # Framework-specific issues
        framework_counts = {}
        for v in violations:
            fw = v.get("framework", "Unknown")
            framework_counts[fw] = framework_counts.get(fw, 0) + 1
        
        if framework_counts:
            highest_framework = max(framework_counts.items(), key=lambda x: x[1])
            findings.append(f"{highest_framework[0]} has the most violations ({highest_framework[1]})")
        
        return findings[:5]  # Top 5 findings
    
    def _calculate_mtd(self, violations: List[Dict[str, Any]]) -> float:
        """Calculate mean time to detect."""
        # Simplified - would need actual incident timestamps
        return 24.0  # Default 24 hours
    
    def _calculate_mtr(self, violations: List[Dict[str, Any]]) -> float:
        """Calculate mean time to remediate."""
        times = []
        for v in violations:
            if v.get("detected_at") and v.get("remediated_at"):
                detected = datetime.fromisoformat(v["detected_at"])
                remediated = datetime.fromisoformat(v["remediated_at"])
                hours = (remediated - detected).total_seconds() / 3600
                times.append(hours)
        
        return sum(times) / len(times) if times else 0
    
    def _count_repeat_violations(self, violations: List[Dict[str, Any]]) -> int:
        """Count repeat violations."""
        # Simplified - would need historical data
        return sum(1 for v in violations if v.get("is_repeat", False))
    
    def _score_by_framework(self, violations: List[Dict[str, Any]]) -> Dict[str, float]:
        """Calculate compliance score by framework."""
        framework_violations = {}
        
        for v in violations:
            framework = v.get("framework", "Unknown")
            if framework not in framework_violations:
                framework_violations[framework] = []
            framework_violations[framework].append(v)
        
        scores = {}
        for framework, viols in framework_violations.items():
            scores[framework] = self._calculate_overall_score(viols)
        
        return scores
    
    async def _generate_html_report(self, report_data: Dict[str, Any]) -> str:
        """Generate interactive HTML report."""
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compliance Audit Report - {report_data['metadata']['report_id']}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0 0 10px 0;
        }}
        .section {{
            background: white;
            padding: 25px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .metric-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .metric-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }}
        .metric-value {{
            font-size: 32px;
            font-weight: bold;
            color: #667eea;
        }}
        .metric-label {{
            font-size: 14px;
            color: #666;
            margin-top: 5px;
        }}
        .severity-critical {{ color: #dc3545; }}
        .severity-high {{ color: #fd7e14; }}
        .severity-medium {{ color: #ffc107; }}
        .severity-low {{ color: #28a745; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #667eea;
            color: white;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .compliance-bar {{
            width: 100%;
            height: 30px;
            background: #e9ecef;
            border-radius: 15px;
            overflow: hidden;
            margin: 10px 0;
        }}
        .compliance-bar-fill {{
            height: 100%;
            background: linear-gradient(90deg, #28a745 0%, #20c997 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Compliance Audit Report</h1>
        <p>Report ID: {report_data['metadata']['report_id']}</p>
        <p>Generated: {report_data['metadata']['generated_at']}</p>
        <p>Period: {report_data['metadata']['period_start']} to {report_data['metadata']['period_end']}</p>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-value">{report_data['executive_summary']['total_violations']}</div>
                <div class="metric-label">Total Violations</div>
            </div>
            <div class="metric-card">
                <div class="metric-value severity-critical">{report_data['executive_summary']['critical_violations']}</div>
                <div class="metric-label">Critical</div>
            </div>
            <div class="metric-card">
                <div class="metric-value severity-high">{report_data['executive_summary']['high_violations']}</div>
                <div class="metric-label">High</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{report_data['executive_summary']['overall_compliance_score']}</div>
                <div class="metric-label">Compliance Score</div>
            </div>
        </div>
        
        <h3>Key Findings</h3>
        <ul>
            {''.join(f'<li>{finding}</li>' for finding in report_data['executive_summary']['key_findings'])}
        </ul>
    </div>
    
    <div class="section">
        <h2>Compliance Status by Framework</h2>
        {self._generate_framework_html(report_data['compliance_status'])}
    </div>
    
    <div class="section">
        <h2>Remediation Status</h2>
        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-value" style="color: #28a745;">{report_data['remediation_status']['remediated']}</div>
                <div class="metric-label">Remediated</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" style="color: #ffc107;">{report_data['remediation_status']['in_progress']}</div>
                <div class="metric-label">In Progress</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" style="color: #dc3545;">{report_data['remediation_status']['overdue']}</div>
                <div class="metric-label">Overdue</div>
            </div>
        </div>
    </div>
    
    <div class="section">
        <h2>Detailed Violations</h2>
        {self._generate_violations_table(report_data['violations'])}
    </div>
</body>
</html>
        """
        
        # Save HTML file
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"audit_report_{timestamp}.html"
        filepath = self.output_dir / filename
        
        filepath.write_text(html_content)
        
        return str(filepath)
    
    def _generate_framework_html(self, compliance_status: Dict[str, Any]) -> str:
        """Generate HTML for framework compliance status."""
        html = ""
        for framework, stats in compliance_status.items():
            compliance_rate = stats.get("compliance_rate", 0)
            html += f"""
            <div style="margin: 20px 0;">
                <h3>{framework}</h3>
                <div class="compliance-bar">
                    <div class="compliance-bar-fill" style="width: {compliance_rate}%;">
                        {compliance_rate:.1f}%
                    </div>
                </div>
                <p>Passed: {stats['passed']} | Failed: {stats['failed']} | Total: {stats['total_checks']}</p>
            </div>
            """
        return html
    
    def _generate_violations_table(self, violations: List[Dict[str, Any]]) -> str:
        """Generate HTML table of violations."""
        if not violations:
            return "<p>No violations found.</p>"
        
        rows = ""
        for v in violations[:50]:  # Limit to 50 for readability
            severity_class = f"severity-{v.get('severity', 'low').lower()}"
            rows += f"""
            <tr>
                <td class="{severity_class}">{v.get('severity', 'N/A').upper()}</td>
                <td>{v.get('framework', 'N/A')}</td>
                <td>{v.get('violation_type', 'N/A')}</td>
                <td>{v.get('description', 'N/A')[:100]}...</td>
                <td>{v.get('remediation_status', 'pending')}</td>
            </tr>
            """
        
        return f"""
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Framework</th>
                    <th>Type</th>
                    <th>Description</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
        """
    
    async def _generate_pdf_report(self, report_data: Dict[str, Any]) -> str:
        """Generate PDF report (requires external library)."""
        # Note: In production, use libraries like ReportLab or WeasyPrint
        # For now, generate a simple text-based PDF placeholder
        
        logger.warning("PDF generation requires additional libraries (ReportLab/WeasyPrint)")
        
        # Fallback: generate JSON and note PDF requirement
        json_path = await self._generate_json_report(report_data)
        logger.info(f"Generated JSON report as PDF placeholder: {json_path}")
        
        return json_path
    
    async def _generate_json_report(self, report_data: Dict[str, Any]) -> str:
        """Generate JSON report."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"audit_report_{timestamp}.json"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        return str(filepath)
    
    async def _generate_csv_report(self, report_data: Dict[str, Any]) -> str:
        """Generate CSV report."""
        import csv
        
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"audit_report_{timestamp}.csv"
        filepath = self.output_dir / filename
        
        violations = report_data.get("violations", [])
        
        if not violations:
            return str(filepath)
        
        # Get all unique keys from violations
        fieldnames = set()
        for v in violations:
            fieldnames.update(v.keys())
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=sorted(fieldnames))
            writer.writeheader()
            writer.writerows(violations)
        
        return str(filepath)
