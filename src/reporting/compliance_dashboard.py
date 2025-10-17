"""Real-time compliance dashboard with metrics and visualization."""

from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from collections import defaultdict

from ..utils.logger import get_logger

logger = get_logger(__name__)


class ComplianceDashboard:
    """
    Real-time compliance dashboard.
    
    Provides:
    - Live metrics
    - Violation tracking
    - Compliance trends
    - Framework-specific views
    - Alerting
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize compliance dashboard."""
        self.config = config or {}
        self.metrics_cache = {}
        self.cache_ttl = 300  # 5 minutes
    
    async def get_dashboard_data(
        self,
        timeframe: str = "7d",
        frameworks: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Get complete dashboard data."""
        try:
            logger.info(f"Generating dashboard data for timeframe: {timeframe}")
            
            # Check cache
            cache_key = f"{timeframe}_{frameworks}"
            cached = self._get_cached_metrics(cache_key)
            if cached:
                return cached
            
            # Generate dashboard data
            dashboard = {
                "generated_at": datetime.utcnow().isoformat(),
                "timeframe": timeframe,
                "overview": await self._get_overview_metrics(timeframe, frameworks),
                "violations": await self._get_violation_metrics(timeframe, frameworks),
                "compliance_scores": await self._get_compliance_scores(frameworks),
                "trends": await self._get_trend_data(timeframe, frameworks),
                "alerts": await self._get_active_alerts(frameworks),
                "remediation": await self._get_remediation_metrics(timeframe, frameworks),
                "risk_distribution": await self._get_risk_distribution(frameworks)
            }
            
            # Cache results
            self._cache_metrics(cache_key, dashboard)
            
            return dashboard
        
        except Exception as e:
            logger.error(f"Failed to generate dashboard data: {e}")
            raise
    
    async def _get_overview_metrics(
        self,
        timeframe: str,
        frameworks: Optional[List[str]]
    ) -> Dict[str, Any]:
        """Get overview metrics."""
        # In production, query from database
        # For now, return placeholder data
        
        return {
            "total_violations": 127,
            "critical_violations": 8,
            "high_violations": 23,
            "medium_violations": 54,
            "low_violations": 42,
            "compliance_score": 78.5,
            "score_change": +3.2,  # vs previous period
            "active_incidents": 5,
            "overdue_remediations": 12,
            "frameworks_monitored": frameworks or ["GDPR", "HIPAA", "PCI_DSS"],
            "systems_scanned": 245,
            "last_scan": datetime.utcnow().isoformat()
        }
    
    async def _get_violation_metrics(
        self,
        timeframe: str,
        frameworks: Optional[List[str]]
    ) -> Dict[str, Any]:
        """Get violation metrics."""
        return {
            "total": 127,
            "new_today": 8,
            "new_this_week": 34,
            "by_framework": {
                "GDPR": 45,
                "HIPAA": 32,
                "PCI_DSS": 28,
                "SOX": 15,
                "CCPA": 7
            },
            "by_type": {
                "data_exposure": 38,
                "encryption_missing": 29,
                "access_control": 25,
                "audit_logging": 20,
                "data_retention": 15
            },
            "by_severity": {
                "critical": 8,
                "high": 23,
                "medium": 54,
                "low": 42
            },
            "top_violations": [
                {
                    "type": "Unencrypted PII storage",
                    "count": 15,
                    "severity": "high",
                    "framework": "GDPR"
                },
                {
                    "type": "Missing audit logs",
                    "count": 12,
                    "severity": "medium",
                    "framework": "HIPAA"
                },
                {
                    "type": "Weak password policy",
                    "count": 10,
                    "severity": "medium",
                    "framework": "PCI_DSS"
                }
            ]
        }
    
    async def _get_compliance_scores(
        self,
        frameworks: Optional[List[str]]
    ) -> Dict[str, Any]:
        """Get compliance scores by framework."""
        scores = {
            "overall": 78.5,
            "by_framework": {
                "GDPR": {
                    "score": 82.3,
                    "trend": "improving",
                    "change": +5.2,
                    "passing_controls": 165,
                    "total_controls": 200
                },
                "HIPAA": {
                    "score": 75.8,
                    "trend": "stable",
                    "change": -0.5,
                    "passing_controls": 121,
                    "total_controls": 160
                },
                "PCI_DSS": {
                    "score": 79.1,
                    "trend": "improving",
                    "change": +3.8,
                    "passing_controls": 95,
                    "total_controls": 120
                },
                "SOX": {
                    "score": 85.4,
                    "trend": "stable",
                    "change": +0.2,
                    "passing_controls": 88,
                    "total_controls": 103
                }
            },
            "target_score": 90.0,
            "gap_to_target": 11.5
        }
        
        # Filter by requested frameworks
        if frameworks:
            scores["by_framework"] = {
                k: v for k, v in scores["by_framework"].items()
                if k in frameworks
            }
        
        return scores
    
    async def _get_trend_data(
        self,
        timeframe: str,
        frameworks: Optional[List[str]]
    ) -> Dict[str, Any]:
        """Get trend data over time."""
        # Generate time-series data
        days = self._parse_timeframe(timeframe)
        
        # Simulate trend data (in production, query from database)
        dates = []
        compliance_scores = []
        violation_counts = []
        
        base_date = datetime.utcnow() - timedelta(days=days)
        for i in range(days):
            date = base_date + timedelta(days=i)
            dates.append(date.strftime("%Y-%m-%d"))
            
            # Simulate improving trend
            compliance_scores.append(round(75 + (i * 0.5), 1))
            violation_counts.append(max(100 - i * 2, 50))
        
        return {
            "dates": dates,
            "compliance_scores": compliance_scores,
            "violation_counts": violation_counts,
            "remediation_rate": [round(60 + (i * 1.2), 1) for i in range(days)],
            "mean_time_to_remediate": [48 - i * 0.5 for i in range(days)]  # hours
        }
    
    async def _get_active_alerts(
        self,
        frameworks: Optional[List[str]]
    ) -> List[Dict[str, Any]]:
        """Get active alerts."""
        alerts = [
            {
                "alert_id": "ALT-001",
                "severity": "critical",
                "title": "Multiple critical GDPR violations detected",
                "description": "8 critical violations detected in production environment",
                "framework": "GDPR",
                "triggered_at": (datetime.utcnow() - timedelta(hours=2)).isoformat(),
                "status": "active"
            },
            {
                "alert_id": "ALT-002",
                "severity": "high",
                "title": "Compliance score below threshold",
                "description": "PCI DSS compliance score dropped below 80%",
                "framework": "PCI_DSS",
                "triggered_at": (datetime.utcnow() - timedelta(hours=6)).isoformat(),
                "status": "acknowledged"
            },
            {
                "alert_id": "ALT-003",
                "severity": "medium",
                "title": "Overdue remediations",
                "description": "12 remediations past their due date",
                "framework": "HIPAA",
                "triggered_at": (datetime.utcnow() - timedelta(days=1)).isoformat(),
                "status": "active"
            }
        ]
        
        # Filter by framework
        if frameworks:
            alerts = [a for a in alerts if a["framework"] in frameworks]
        
        return alerts
    
    async def _get_remediation_metrics(
        self,
        timeframe: str,
        frameworks: Optional[List[str]]
    ) -> Dict[str, Any]:
        """Get remediation metrics."""
        return {
            "total_violations": 127,
            "remediated": 78,
            "in_progress": 37,
            "pending": 12,
            "overdue": 12,
            "remediation_rate": 61.4,  # percentage
            "average_time_to_remediate": 36.5,  # hours
            "by_severity": {
                "critical": {
                    "total": 8,
                    "remediated": 3,
                    "avg_time": 12.5
                },
                "high": {
                    "total": 23,
                    "remediated": 15,
                    "avg_time": 24.3
                },
                "medium": {
                    "total": 54,
                    "remediated": 38,
                    "avg_time": 48.7
                },
                "low": {
                    "total": 42,
                    "remediated": 22,
                    "avg_time": 72.1
                }
            },
            "top_remediators": [
                {"name": "Security Team", "remediated": 45},
                {"name": "DevOps Team", "remediated": 22},
                {"name": "Data Team", "remediated": 11}
            ]
        }
    
    async def _get_risk_distribution(
        self,
        frameworks: Optional[List[str]]
    ) -> Dict[str, Any]:
        """Get risk distribution."""
        return {
            "by_severity": {
                "critical": 6.3,  # percentage
                "high": 18.1,
                "medium": 42.5,
                "low": 33.1
            },
            "by_risk_score": {
                "0-20": 15,
                "21-40": 42,
                "41-60": 38,
                "61-80": 23,
                "81-100": 9
            },
            "high_risk_areas": [
                {
                    "area": "Data Storage",
                    "risk_score": 78,
                    "violations": 34
                },
                {
                    "area": "Access Control",
                    "risk_score": 72,
                    "violations": 25
                },
                {
                    "area": "Encryption",
                    "risk_score": 68,
                    "violations": 29
                }
            ]
        }
    
    def _parse_timeframe(self, timeframe: str) -> int:
        """Parse timeframe string to days."""
        import re
        
        match = re.match(r'(\d+)([dDwWmMyY])', timeframe)
        if not match:
            return 7  # Default 7 days
        
        value = int(match.group(1))
        unit = match.group(2).lower()
        
        if unit == 'd':
            return value
        elif unit == 'w':
            return value * 7
        elif unit == 'm':
            return value * 30
        elif unit == 'y':
            return value * 365
        
        return 7
    
    def _get_cached_metrics(self, key: str) -> Optional[Dict[str, Any]]:
        """Get cached metrics if still valid."""
        if key in self.metrics_cache:
            cached_data, timestamp = self.metrics_cache[key]
            if (datetime.utcnow() - timestamp).total_seconds() < self.cache_ttl:
                logger.info(f"Using cached dashboard data for {key}")
                return cached_data
        
        return None
    
    def _cache_metrics(self, key: str, data: Dict[str, Any]):
        """Cache metrics data."""
        self.metrics_cache[key] = (data, datetime.utcnow())
    
    async def get_framework_dashboard(self, framework: str) -> Dict[str, Any]:
        """Get framework-specific dashboard."""
        return {
            "framework": framework,
            "compliance_score": await self._get_framework_score(framework),
            "violations": await self._get_framework_violations(framework),
            "controls": await self._get_framework_controls(framework),
            "recent_scans": await self._get_framework_scans(framework),
            "remediation_status": await self._get_framework_remediation(framework)
        }
    
    async def _get_framework_score(self, framework: str) -> Dict[str, Any]:
        """Get compliance score for specific framework."""
        # Placeholder data
        scores = {
            "GDPR": 82.3,
            "HIPAA": 75.8,
            "PCI_DSS": 79.1,
            "SOX": 85.4,
            "CCPA": 80.2
        }
        
        return {
            "score": scores.get(framework, 75.0),
            "grade": self._score_to_grade(scores.get(framework, 75.0)),
            "trend": "improving",
            "last_updated": datetime.utcnow().isoformat()
        }
    
    async def _get_framework_violations(self, framework: str) -> Dict[str, Any]:
        """Get violations for specific framework."""
        # Placeholder
        return {
            "total": 45,
            "critical": 3,
            "high": 12,
            "medium": 20,
            "low": 10
        }
    
    async def _get_framework_controls(self, framework: str) -> Dict[str, Any]:
        """Get control status for framework."""
        # Placeholder
        return {
            "total_controls": 200,
            "passing": 165,
            "failing": 35,
            "compliance_rate": 82.5
        }
    
    async def _get_framework_scans(self, framework: str) -> List[Dict[str, Any]]:
        """Get recent scans for framework."""
        # Placeholder
        return [
            {
                "scan_id": "SCN-001",
                "timestamp": (datetime.utcnow() - timedelta(hours=1)).isoformat(),
                "violations_found": 3,
                "duration": "2m 34s"
            },
            {
                "scan_id": "SCN-002",
                "timestamp": (datetime.utcnow() - timedelta(hours=25)).isoformat(),
                "violations_found": 5,
                "duration": "2m 18s"
            }
        ]
    
    async def _get_framework_remediation(self, framework: str) -> Dict[str, Any]:
        """Get remediation status for framework."""
        # Placeholder
        return {
            "total": 45,
            "remediated": 28,
            "in_progress": 12,
            "pending": 5,
            "rate": 62.2
        }
    
    def _score_to_grade(self, score: float) -> str:
        """Convert score to letter grade."""
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"
    
    async def export_dashboard_data(
        self,
        format: str = "json",
        timeframe: str = "7d"
    ) -> str:
        """Export dashboard data."""
        dashboard = await self.get_dashboard_data(timeframe)
        
        if format == "json":
            import json
            from pathlib import Path
            
            output_dir = Path("./exports")
            output_dir.mkdir(exist_ok=True)
            
            filename = f"dashboard_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            filepath = output_dir / filename
            
            with open(filepath, 'w') as f:
                json.dump(dashboard, f, indent=2, default=str)
            
            return str(filepath)
        
        else:
            raise ValueError(f"Unsupported export format: {format}")
