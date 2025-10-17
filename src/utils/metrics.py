"""Metrics calculation utilities for Compliance Guardian AI."""

import math
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

from .logger import get_logger

logger = get_logger(__name__)


class ComplianceFramework(Enum):
    """Supported compliance frameworks with weights."""
    GDPR = {"weight": 1.0, "critical_penalty": 0.3}
    HIPAA = {"weight": 0.9, "critical_penalty": 0.25}
    PCI_DSS = {"weight": 0.8, "critical_penalty": 0.2}
    SOX = {"weight": 0.7, "critical_penalty": 0.15}
    ISO_27001 = {"weight": 0.6, "critical_penalty": 0.1}
    CCPA = {"weight": 0.8, "critical_penalty": 0.2}


class SeverityLevel(Enum):
    """Severity levels with scoring weights."""
    CRITICAL = 1.0
    HIGH = 0.7
    MEDIUM = 0.4
    LOW = 0.2
    INFO = 0.1


@dataclass
class ComplianceMetrics:
    """Container for compliance metrics."""
    
    total_violations: int = 0
    critical_violations: int = 0
    high_violations: int = 0
    medium_violations: int = 0
    low_violations: int = 0
    info_violations: int = 0
    
    resolved_violations: int = 0
    pending_violations: int = 0
    false_positives: int = 0
    
    compliance_score: float = 0.0
    risk_score: float = 0.0
    
    framework_scores: Dict[str, float] = None
    trend_direction: str = "stable"  # improving, degrading, stable
    
    def __post_init__(self):
        if self.framework_scores is None:
            self.framework_scores = {}


@dataclass
class RiskFactors:
    """Risk assessment factors."""
    
    data_sensitivity: float = 0.5  # 0.0 to 1.0
    exposure_level: float = 0.5    # 0.0 to 1.0
    system_criticality: float = 0.5  # 0.0 to 1.0
    regulatory_impact: float = 0.5   # 0.0 to 1.0
    
    # Historical factors
    past_incidents: int = 0
    remediation_time_avg: float = 0.0  # days
    false_positive_rate: float = 0.0   # 0.0 to 1.0


def calculate_compliance_score(
    violations: List[Dict[str, Any]],
    total_checks: int,
    framework_weights: Optional[Dict[str, float]] = None
) -> float:
    """
    Calculate overall compliance score based on violations.
    
    Args:
        violations: List of violation records
        total_checks: Total number of compliance checks performed
        framework_weights: Optional custom framework weights
        
    Returns:
        Compliance score between 0.0 and 100.0
    """
    try:
        if total_checks == 0:
            logger.warning("Cannot calculate compliance score with zero checks")
            return 0.0
        
        if not violations:
            return 100.0
        
        # Default framework weights
        if not framework_weights:
            framework_weights = {
                "GDPR": 1.0,
                "HIPAA": 0.9,
                "PCI_DSS": 0.8,
                "SOX": 0.7,
                "ISO_27001": 0.6,
                "CCPA": 0.8
            }
        
        # Calculate weighted violation score
        total_violation_weight = 0.0
        max_possible_weight = 0.0
        
        framework_violation_counts = {}
        
        for violation in violations:
            framework = violation.get("framework", "UNKNOWN")
            severity = violation.get("severity", "MEDIUM").upper()
            
            # Get framework weight
            framework_weight = framework_weights.get(framework, 0.5)
            
            # Get severity weight
            try:
                severity_weight = SeverityLevel[severity].value
            except KeyError:
                severity_weight = SeverityLevel.MEDIUM.value
                logger.warning(f"Unknown severity level: {severity}")
            
            # Calculate violation weight
            violation_weight = framework_weight * severity_weight
            total_violation_weight += violation_weight
            
            # Track by framework
            if framework not in framework_violation_counts:
                framework_violation_counts[framework] = 0
            framework_violation_counts[framework] += 1
        
        # Calculate maximum possible weight (all checks as critical violations)
        for framework, weight in framework_weights.items():
            # Estimate checks per framework (simplified)
            checks_per_framework = total_checks / len(framework_weights)
            max_possible_weight += checks_per_framework * weight * SeverityLevel.CRITICAL.value
        
        # Calculate compliance score
        if max_possible_weight > 0:
            violation_ratio = total_violation_weight / max_possible_weight
            compliance_score = max(0.0, (1.0 - violation_ratio) * 100.0)
        else:
            compliance_score = 100.0
        
        logger.info(
            f"Compliance score calculated: {compliance_score:.2f}",
            extra={
                "total_violations": len(violations),
                "total_checks": total_checks,
                "violation_weight": total_violation_weight,
                "max_weight": max_possible_weight,
                "framework_counts": framework_violation_counts
            }
        )
        
        return min(100.0, max(0.0, compliance_score))
        
    except Exception as e:
        logger.error(f"Failed to calculate compliance score: {e}")
        return 0.0


def calculate_risk_score(
    violations: List[Dict[str, Any]],
    risk_factors: RiskFactors,
    historical_data: Optional[Dict[str, Any]] = None
) -> float:
    """
    Calculate risk score based on violations and risk factors.
    
    Args:
        violations: List of violation records
        risk_factors: Risk assessment factors
        historical_data: Optional historical metrics
        
    Returns:
        Risk score between 0.0 and 100.0 (higher = more risky)
    """
    try:
        if not violations and risk_factors.past_incidents == 0:
            return 0.0
        
        # Base risk from current violations
        violation_risk = 0.0
        critical_multiplier = 1.0
        
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        
        for violation in violations:
            severity = violation.get("severity", "MEDIUM").upper()
            framework = violation.get("framework", "UNKNOWN")
            
            # Count by severity
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            # Get severity risk contribution
            try:
                severity_risk = SeverityLevel[severity].value
            except KeyError:
                severity_risk = SeverityLevel.MEDIUM.value
            
            # Framework-specific risk multiplier
            framework_multiplier = ComplianceFramework.__members__.get(
                framework, ComplianceFramework.ISO_27001
            ).value.get("critical_penalty", 0.1)
            
            violation_risk += severity_risk * (1.0 + framework_multiplier)
        
        # Critical violation penalty
        if severity_counts["CRITICAL"] > 0:
            critical_multiplier = 1.0 + (severity_counts["CRITICAL"] * 0.2)
        
        # Environmental risk factors
        environment_risk = (
            risk_factors.data_sensitivity * 0.25 +
            risk_factors.exposure_level * 0.25 +
            risk_factors.system_criticality * 0.2 +
            risk_factors.regulatory_impact * 0.3
        ) * 100
        
        # Historical risk factors
        historical_risk = 0.0
        if risk_factors.past_incidents > 0:
            # Risk increases with past incidents
            historical_risk = min(30.0, risk_factors.past_incidents * 5.0)
        
        if risk_factors.remediation_time_avg > 7.0:  # More than a week
            # Slow remediation increases risk
            historical_risk += min(20.0, (risk_factors.remediation_time_avg - 7.0) * 2.0)
        
        if risk_factors.false_positive_rate > 0.3:  # High false positive rate
            # High false positives reduce trust in system
            historical_risk += min(15.0, (risk_factors.false_positive_rate - 0.3) * 30.0)
        
        # Combine risk components
        base_risk = min(50.0, violation_risk * 10.0) * critical_multiplier
        total_risk = base_risk + environment_risk + historical_risk
        
        # Normalize to 0-100 scale
        normalized_risk = min(100.0, max(0.0, total_risk))
        
        logger.info(
            f"Risk score calculated: {normalized_risk:.2f}",
            extra={
                "base_risk": base_risk,
                "environment_risk": environment_risk,
                "historical_risk": historical_risk,
                "critical_multiplier": critical_multiplier,
                "severity_counts": severity_counts
            }
        )
        
        return normalized_risk
        
    except Exception as e:
        logger.error(f"Failed to calculate risk score: {e}")
        return 50.0  # Return moderate risk on error


def calculate_framework_scores(
    violations: List[Dict[str, Any]],
    framework_checks: Dict[str, int]
) -> Dict[str, float]:
    """
    Calculate compliance scores for individual frameworks.
    
    Args:
        violations: List of violation records
        framework_checks: Number of checks per framework
        
    Returns:
        Dictionary of framework scores
    """
    try:
        framework_scores = {}
        
        # Group violations by framework
        framework_violations = {}
        for violation in violations:
            framework = violation.get("framework", "UNKNOWN")
            if framework not in framework_violations:
                framework_violations[framework] = []
            framework_violations[framework].append(violation)
        
        # Calculate score for each framework
        for framework, checks in framework_checks.items():
            if checks == 0:
                framework_scores[framework] = 100.0
                continue
            
            framework_viols = framework_violations.get(framework, [])
            
            if not framework_viols:
                framework_scores[framework] = 100.0
            else:
                # Calculate weighted violation score for this framework
                violation_weight = 0.0
                for violation in framework_viols:
                    severity = violation.get("severity", "MEDIUM").upper()
                    try:
                        severity_weight = SeverityLevel[severity].value
                    except KeyError:
                        severity_weight = SeverityLevel.MEDIUM.value
                    
                    violation_weight += severity_weight
                
                # Calculate score
                max_weight = checks * SeverityLevel.CRITICAL.value
                if max_weight > 0:
                    violation_ratio = violation_weight / max_weight
                    score = max(0.0, (1.0 - violation_ratio) * 100.0)
                else:
                    score = 100.0
                
                framework_scores[framework] = min(100.0, max(0.0, score))
        
        return framework_scores
        
    except Exception as e:
        logger.error(f"Failed to calculate framework scores: {e}")
        return {}


def calculate_trend_direction(
    current_metrics: ComplianceMetrics,
    historical_metrics: List[ComplianceMetrics],
    lookback_days: int = 30
) -> str:
    """
    Calculate trend direction based on historical data.
    
    Args:
        current_metrics: Current compliance metrics
        historical_metrics: Historical metrics data
        lookback_days: Number of days to look back
        
    Returns:
        Trend direction: "improving", "degrading", or "stable"
    """
    try:
        if len(historical_metrics) < 2:
            return "stable"
        
        # Get recent metrics (last 7 days vs previous period)
        recent_scores = []
        older_scores = []
        
        cutoff_date = datetime.now() - timedelta(days=7)
        
        for metrics in historical_metrics[-lookback_days:]:
            if hasattr(metrics, 'timestamp'):
                if metrics.timestamp > cutoff_date:
                    recent_scores.append(metrics.compliance_score)
                else:
                    older_scores.append(metrics.compliance_score)
        
        if not recent_scores or not older_scores:
            return "stable"
        
        recent_avg = sum(recent_scores) / len(recent_scores)
        older_avg = sum(older_scores) / len(older_scores)
        
        # Calculate percentage change
        if older_avg > 0:
            change_percent = ((recent_avg - older_avg) / older_avg) * 100
        else:
            change_percent = 0
        
        # Determine trend
        if change_percent > 5.0:
            return "improving"
        elif change_percent < -5.0:
            return "degrading"
        else:
            return "stable"
            
    except Exception as e:
        logger.error(f"Failed to calculate trend direction: {e}")
        return "stable"


def calculate_remediation_priority(
    violation: Dict[str, Any],
    risk_factors: RiskFactors
) -> float:
    """
    Calculate priority score for violation remediation.
    
    Args:
        violation: Violation record
        risk_factors: Risk assessment factors
        
    Returns:
        Priority score between 0.0 and 100.0 (higher = more urgent)
    """
    try:
        base_priority = 0.0
        
        # Severity contribution (40% of priority)
        severity = violation.get("severity", "MEDIUM").upper()
        try:
            severity_weight = SeverityLevel[severity].value
        except KeyError:
            severity_weight = SeverityLevel.MEDIUM.value
        
        base_priority += severity_weight * 40.0
        
        # Framework impact (25% of priority)
        framework = violation.get("framework", "UNKNOWN")
        try:
            framework_info = ComplianceFramework[framework].value
            framework_weight = framework_info["weight"]
        except KeyError:
            framework_weight = 0.5
        
        base_priority += framework_weight * 25.0
        
        # Data sensitivity (20% of priority)
        base_priority += risk_factors.data_sensitivity * 20.0
        
        # System exposure (15% of priority)
        base_priority += risk_factors.exposure_level * 15.0
        
        # Age penalty (newer violations get higher priority)
        violation_age_days = violation.get("age_days", 0)
        age_penalty = max(0.0, min(10.0, violation_age_days * 0.5))
        
        final_priority = base_priority + age_penalty
        
        return min(100.0, max(0.0, final_priority))
        
    except Exception as e:
        logger.error(f"Failed to calculate remediation priority: {e}")
        return 50.0


def calculate_cost_impact(
    violations: List[Dict[str, Any]],
    hourly_rate: float = 150.0,
    base_fine_amounts: Optional[Dict[str, float]] = None
) -> Dict[str, float]:
    """
    Calculate estimated cost impact of violations.
    
    Args:
        violations: List of violation records
        hourly_rate: Hourly cost for remediation work
        base_fine_amounts: Base fine amounts per framework
        
    Returns:
        Dictionary with cost breakdown
    """
    try:
        if not base_fine_amounts:
            base_fine_amounts = {
                "GDPR": 20000000.0,  # €20M max fine
                "HIPAA": 1500000.0,  # $1.5M typical fine
                "PCI_DSS": 500000.0, # $500K typical fine
                "SOX": 5000000.0,    # $5M max fine
                "ISO_27001": 100000.0, # $100K certification cost
                "CCPA": 2500000.0    # $2.5M max fine
            }
        
        remediation_cost = 0.0
        potential_fine_cost = 0.0
        
        severity_hours = {
            "CRITICAL": 40.0,
            "HIGH": 20.0,
            "MEDIUM": 8.0,
            "LOW": 4.0,
            "INFO": 1.0
        }
        
        for violation in violations:
            severity = violation.get("severity", "MEDIUM").upper()
            framework = violation.get("framework", "UNKNOWN")
            
            # Remediation cost
            hours = severity_hours.get(severity, 8.0)
            remediation_cost += hours * hourly_rate
            
            # Potential fine risk
            base_fine = base_fine_amounts.get(framework, 100000.0)
            
            # Risk probability based on severity
            risk_probability = {
                "CRITICAL": 0.15,  # 15% chance of fine
                "HIGH": 0.08,      # 8% chance
                "MEDIUM": 0.03,    # 3% chance
                "LOW": 0.01,       # 1% chance
                "INFO": 0.001      # 0.1% chance
            }.get(severity, 0.03)
            
            potential_fine_cost += base_fine * risk_probability
        
        total_cost = remediation_cost + potential_fine_cost
        
        return {
            "remediation_cost": remediation_cost,
            "potential_fine_cost": potential_fine_cost,
            "total_estimated_cost": total_cost,
            "cost_breakdown": {
                "labor": remediation_cost,
                "risk": potential_fine_cost
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to calculate cost impact: {e}")
        return {
            "remediation_cost": 0.0,
            "potential_fine_cost": 0.0,
            "total_estimated_cost": 0.0,
            "cost_breakdown": {"labor": 0.0, "risk": 0.0}
        }


def calculate_efficiency_metrics(
    scan_results: List[Dict[str, Any]],
    remediation_results: List[Dict[str, Any]]
) -> Dict[str, float]:
    """
    Calculate system efficiency metrics.
    
    Args:
        scan_results: Results from compliance scans
        remediation_results: Results from remediation actions
        
    Returns:
        Dictionary with efficiency metrics
    """
    try:
        metrics = {
            "scan_accuracy": 0.0,
            "false_positive_rate": 0.0,
            "remediation_success_rate": 0.0,
            "average_remediation_time": 0.0,
            "detection_coverage": 0.0
        }
        
        if not scan_results:
            return metrics
        
        # Calculate false positive rate
        total_violations = len(scan_results)
        false_positives = sum(1 for result in scan_results 
                            if result.get("is_false_positive", False))
        
        if total_violations > 0:
            metrics["false_positive_rate"] = (false_positives / total_violations) * 100
            metrics["scan_accuracy"] = ((total_violations - false_positives) / total_violations) * 100
        
        # Calculate remediation metrics
        if remediation_results:
            successful_remediations = sum(1 for result in remediation_results 
                                        if result.get("status") == "success")
            
            metrics["remediation_success_rate"] = (successful_remediations / len(remediation_results)) * 100
            
            # Average remediation time
            remediation_times = [result.get("duration_hours", 0) 
                               for result in remediation_results 
                               if result.get("duration_hours")]
            
            if remediation_times:
                metrics["average_remediation_time"] = sum(remediation_times) / len(remediation_times)
        
        # Coverage could be calculated based on code coverage, etc.
        # This is a simplified placeholder
        metrics["detection_coverage"] = 85.0  # Placeholder
        
        return metrics
        
    except Exception as e:
        logger.error(f"Failed to calculate efficiency metrics: {e}")
        return {
            "scan_accuracy": 0.0,
            "false_positive_rate": 0.0,
            "remediation_success_rate": 0.0,
            "average_remediation_time": 0.0,
            "detection_coverage": 0.0
        }


def generate_compliance_report_metrics(
    violations: List[Dict[str, Any]],
    historical_data: Optional[List[Dict[str, Any]]] = None,
    risk_factors: Optional[RiskFactors] = None
) -> ComplianceMetrics:
    """
    Generate comprehensive compliance metrics for reporting.
    
    Args:
        violations: Current violations
        historical_data: Historical violation data
        risk_factors: Risk assessment factors
        
    Returns:
        Complete compliance metrics
    """
    try:
        metrics = ComplianceMetrics()
        
        # Count violations by severity
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        
        for violation in violations:
            severity = violation.get("severity", "MEDIUM").upper()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        metrics.total_violations = len(violations)
        metrics.critical_violations = severity_counts["CRITICAL"]
        metrics.high_violations = severity_counts["HIGH"]
        metrics.medium_violations = severity_counts["MEDIUM"]
        metrics.low_violations = severity_counts["LOW"]
        metrics.info_violations = severity_counts["INFO"]
        
        # Count resolved/pending
        metrics.resolved_violations = sum(1 for v in violations if v.get("status") == "resolved")
        metrics.pending_violations = metrics.total_violations - metrics.resolved_violations
        metrics.false_positives = sum(1 for v in violations if v.get("is_false_positive", False))
        
        # Calculate scores
        total_checks = max(100, metrics.total_violations * 2)  # Estimate
        metrics.compliance_score = calculate_compliance_score(violations, total_checks)
        
        if risk_factors:
            metrics.risk_score = calculate_risk_score(violations, risk_factors)
        
        # Framework scores
        framework_checks = {"GDPR": 50, "HIPAA": 40, "PCI_DSS": 30}  # Estimates
        metrics.framework_scores = calculate_framework_scores(violations, framework_checks)
        
        # Trend direction (simplified without historical data)
        if historical_data:
            # Would implement proper trend calculation here
            metrics.trend_direction = "stable"
        
        return metrics
        
    except Exception as e:
        logger.error(f"Failed to generate compliance report metrics: {e}")
        return ComplianceMetrics()