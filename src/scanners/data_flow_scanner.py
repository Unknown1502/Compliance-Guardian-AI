"""Data flow scanner for compliance."""

from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum

from ..utils.logger import get_logger

logger = get_logger(__name__)


class DataClassification(Enum):
    """Data classification levels."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    PII = "pii"
    PHI = "phi"
    PCI = "pci"


@dataclass
class DataFlowViolation:
    """Data flow compliance violation."""
    
    flow_id: str
    source: str
    destination: str
    data_classification: str
    violation_type: str
    severity: str
    description: str
    evidence: Dict[str, Any]
    remediation: str


class DataFlowScanner:
    """
    Data flow analysis scanner for compliance.
    
    Tracks and validates:
    - Data movement across systems and boundaries
    - Cross-border data transfers
    - Encryption in transit
    - Access controls on data paths
    - Data retention policies
    - Third-party data sharing
    - Data minimization
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize data flow scanner."""
        self.config = config or {}
        self.violations: List[DataFlowViolation] = []
        self.data_flows: List[Dict[str, Any]] = []
        
        # Geographic regions for cross-border transfer detection
        self.eu_countries = {'AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 
                            'GR', 'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 
                            'RO', 'SK', 'SI', 'ES', 'SE'}
    
    async def scan(self, data_flows: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Perform data flow compliance scan.
        
        Args:
            data_flows: List of data flow definitions with:
                - flow_id: Unique identifier
                - source: Source system/service
                - destination: Destination system/service
                - data_types: List of data classifications
                - encryption: Encryption details
                - source_region: Geographic region of source
                - dest_region: Geographic region of destination
                - purpose: Business purpose
                - retention_days: Data retention period
        """
        try:
            logger.info(f"Starting data flow scan for {len(data_flows)} flows")
            
            self.violations = []
            self.data_flows = data_flows
            
            for flow in data_flows:
                await self._check_encryption_in_transit(flow)
                await self._check_cross_border_transfers(flow)
                await self._check_data_minimization(flow)
                await self._check_retention_policy(flow)
                await self._check_third_party_sharing(flow)
                await self._check_access_controls(flow)
            
            results = {
                "framework": "Data Flow Compliance",
                "flows_analyzed": len(data_flows),
                "violations": [self._violation_to_dict(v) for v in self.violations],
                "violation_count": len(self.violations),
                "flow_map": self._generate_flow_map(),
                "high_risk_flows": self._identify_high_risk_flows(),
                "cross_border_flows": self._identify_cross_border_flows(),
                "recommendations": self._generate_recommendations()
            }
            
            logger.info(f"Data flow scan completed: {len(self.violations)} violations found")
            
            return results
            
        except Exception as e:
            logger.error(f"Data flow scan failed: {e}")
            raise
    
    async def _check_encryption_in_transit(self, flow: Dict[str, Any]) -> None:
        """Check if data is encrypted in transit."""
        encryption = flow.get("encryption", {})
        data_types = flow.get("data_types", [])
        
        # Sensitive data must be encrypted
        sensitive_data = {DataClassification.PII.value, DataClassification.PHI.value, 
                         DataClassification.PCI.value, DataClassification.RESTRICTED.value}
        
        has_sensitive = any(dt in sensitive_data for dt in data_types)
        
        if has_sensitive and not encryption.get("in_transit", False):
            self.violations.append(DataFlowViolation(
                flow_id=flow.get("flow_id", "unknown"),
                source=flow.get("source", "unknown"),
                destination=flow.get("destination", "unknown"),
                data_classification=", ".join(data_types),
                violation_type="unencrypted_transmission",
                severity="critical",
                description="Sensitive data transmitted without encryption",
                evidence={"encryption": encryption, "data_types": data_types},
                remediation="Implement TLS 1.2+ for data in transit"
            ))
        
        # Check encryption strength
        if encryption.get("in_transit") and encryption.get("protocol") in ["SSL", "TLS 1.0", "TLS 1.1"]:
            self.violations.append(DataFlowViolation(
                flow_id=flow.get("flow_id", "unknown"),
                source=flow.get("source", "unknown"),
                destination=flow.get("destination", "unknown"),
                data_classification=", ".join(data_types),
                violation_type="weak_encryption",
                severity="high",
                description="Outdated encryption protocol in use",
                evidence={"protocol": encryption.get("protocol")},
                remediation="Upgrade to TLS 1.2 or higher"
            ))
    
    async def _check_cross_border_transfers(self, flow: Dict[str, Any]) -> None:
        """Check GDPR compliance for cross-border data transfers."""
        source_region = flow.get("source_region", "")
        dest_region = flow.get("dest_region", "")
        data_types = flow.get("data_types", [])
        
        # Check if PII is leaving EU
        has_pii = DataClassification.PII.value in data_types
        source_in_eu = source_region in self.eu_countries
        dest_in_eu = dest_region in self.eu_countries
        
        if has_pii and source_in_eu and not dest_in_eu:
            transfer_mechanism = flow.get("transfer_mechanism", {})
            
            valid_mechanisms = {"standard_contractual_clauses", "adequacy_decision", 
                              "binding_corporate_rules", "consent"}
            
            if not any(transfer_mechanism.get(m, False) for m in valid_mechanisms):
                self.violations.append(DataFlowViolation(
                    flow_id=flow.get("flow_id", "unknown"),
                    source=flow.get("source", "unknown"),
                    destination=flow.get("destination", "unknown"),
                    data_classification=", ".join(data_types),
                    violation_type="gdpr_cross_border",
                    severity="critical",
                    description=f"PII transfer from EU ({source_region}) to non-EU ({dest_region}) without valid mechanism",
                    evidence={"source_region": source_region, "dest_region": dest_region, 
                             "transfer_mechanism": transfer_mechanism},
                    remediation="Implement Standard Contractual Clauses or other valid GDPR transfer mechanism"
                ))
    
    async def _check_data_minimization(self, flow: Dict[str, Any]) -> None:
        """Check GDPR data minimization principle."""
        data_fields = flow.get("data_fields", [])
        purpose = flow.get("purpose", "")
        necessary_fields = flow.get("necessary_fields", [])
        
        if data_fields and necessary_fields:
            unnecessary = set(data_fields) - set(necessary_fields)
            
            if unnecessary:
                self.violations.append(DataFlowViolation(
                    flow_id=flow.get("flow_id", "unknown"),
                    source=flow.get("source", "unknown"),
                    destination=flow.get("destination", "unknown"),
                    data_classification=", ".join(flow.get("data_types", [])),
                    violation_type="data_minimization",
                    severity="medium",
                    description=f"Unnecessary data fields transferred: {', '.join(unnecessary)}",
                    evidence={"unnecessary_fields": list(unnecessary), "purpose": purpose},
                    remediation="Remove unnecessary fields to comply with data minimization principle"
                ))
    
    async def _check_retention_policy(self, flow: Dict[str, Any]) -> None:
        """Check data retention compliance."""
        retention_days = flow.get("retention_days")
        data_types = flow.get("data_types", [])
        destination = flow.get("destination", "")
        
        # Different retention limits for different data types
        retention_limits = {
            DataClassification.PII.value: 365,  # 1 year max unless justified
            DataClassification.PHI.value: 2555,  # 7 years (HIPAA)
            DataClassification.PCI.value: 90,    # 3 months (PCI DSS)
        }
        
        for data_type in data_types:
            limit = retention_limits.get(data_type)
            if limit and retention_days and retention_days > limit:
                self.violations.append(DataFlowViolation(
                    flow_id=flow.get("flow_id", "unknown"),
                    source=flow.get("source", "unknown"),
                    destination=destination,
                    data_classification=data_type,
                    violation_type="excessive_retention",
                    severity="high",
                    description=f"{data_type} retained for {retention_days} days, exceeds {limit} day limit",
                    evidence={"retention_days": retention_days, "limit": limit},
                    remediation=f"Implement data deletion after {limit} days or document business justification"
                ))
    
    async def _check_third_party_sharing(self, flow: Dict[str, Any]) -> None:
        """Check third-party data sharing compliance."""
        destination = flow.get("destination", "")
        is_third_party = flow.get("is_third_party", False)
        data_types = flow.get("data_types", [])
        
        if is_third_party:
            dpa_signed = flow.get("data_processing_agreement", {}).get("signed", False)
            
            if not dpa_signed:
                self.violations.append(DataFlowViolation(
                    flow_id=flow.get("flow_id", "unknown"),
                    source=flow.get("source", "unknown"),
                    destination=destination,
                    data_classification=", ".join(data_types),
                    violation_type="missing_dpa",
                    severity="critical",
                    description="Data shared with third party without Data Processing Agreement",
                    evidence={"third_party": destination, "dpa": flow.get("data_processing_agreement", {})},
                    remediation="Execute Data Processing Agreement with third party before data sharing"
                ))
    
    async def _check_access_controls(self, flow: Dict[str, Any]) -> None:
        """Check access controls on data flow."""
        access_controls = flow.get("access_controls", {})
        data_types = flow.get("data_types", [])
        
        sensitive_data = {DataClassification.PII.value, DataClassification.PHI.value, 
                         DataClassification.PCI.value}
        
        has_sensitive = any(dt in sensitive_data for dt in data_types)
        
        if has_sensitive:
            if not access_controls.get("authentication", False):
                self.violations.append(DataFlowViolation(
                    flow_id=flow.get("flow_id", "unknown"),
                    source=flow.get("source", "unknown"),
                    destination=flow.get("destination", "unknown"),
                    data_classification=", ".join(data_types),
                    violation_type="missing_authentication",
                    severity="critical",
                    description="No authentication required for sensitive data access",
                    evidence={"access_controls": access_controls},
                    remediation="Implement authentication for all sensitive data access"
                ))
            
            if not access_controls.get("authorization", False):
                self.violations.append(DataFlowViolation(
                    flow_id=flow.get("flow_id", "unknown"),
                    source=flow.get("source", "unknown"),
                    destination=flow.get("destination", "unknown"),
                    data_classification=", ".join(data_types),
                    violation_type="missing_authorization",
                    severity="high",
                    description="No role-based authorization for sensitive data",
                    evidence={"access_controls": access_controls},
                    remediation="Implement role-based access control (RBAC) for data access"
                ))
    
    def _generate_flow_map(self) -> Dict[str, Any]:
        """Generate data flow map."""
        flow_map = {
            "sources": set(),
            "destinations": set(),
            "connections": []
        }
        
        for flow in self.data_flows:
            source = flow.get("source", "unknown")
            dest = flow.get("destination", "unknown")
            flow_map["sources"].add(source)
            flow_map["destinations"].add(dest)
            flow_map["connections"].append({
                "from": source,
                "to": dest,
                "data_types": flow.get("data_types", [])
            })
        
        return {
            "sources": list(flow_map["sources"]),
            "destinations": list(flow_map["destinations"]),
            "connections": flow_map["connections"]
        }
    
    def _identify_high_risk_flows(self) -> List[Dict[str, Any]]:
        """Identify high-risk data flows."""
        high_risk = []
        
        for flow in self.data_flows:
            risk_score = 0
            
            # Sensitive data types
            data_types = flow.get("data_types", [])
            if DataClassification.PHI.value in data_types:
                risk_score += 3
            if DataClassification.PCI.value in data_types:
                risk_score += 3
            if DataClassification.PII.value in data_types:
                risk_score += 2
            
            # Third party
            if flow.get("is_third_party", False):
                risk_score += 2
            
            # Cross-border
            if flow.get("source_region") != flow.get("dest_region"):
                risk_score += 2
            
            # Unencrypted
            if not flow.get("encryption", {}).get("in_transit", False):
                risk_score += 3
            
            if risk_score >= 5:
                high_risk.append({
                    "flow_id": flow.get("flow_id"),
                    "source": flow.get("source"),
                    "destination": flow.get("destination"),
                    "risk_score": risk_score,
                    "data_types": data_types
                })
        
        return sorted(high_risk, key=lambda x: x["risk_score"], reverse=True)
    
    def _identify_cross_border_flows(self) -> List[Dict[str, Any]]:
        """Identify cross-border data flows."""
        cross_border = []
        
        for flow in self.data_flows:
            source_region = flow.get("source_region", "")
            dest_region = flow.get("dest_region", "")
            
            if source_region and dest_region and source_region != dest_region:
                cross_border.append({
                    "flow_id": flow.get("flow_id"),
                    "source": flow.get("source"),
                    "source_region": source_region,
                    "destination": flow.get("destination"),
                    "dest_region": dest_region,
                    "data_types": flow.get("data_types", [])
                })
        
        return cross_border
    
    def _generate_recommendations(self) -> List[Dict[str, Any]]:
        """Generate prioritized recommendations."""
        recommendations = []
        by_type = {}
        
        for v in self.violations:
            if v.violation_type not in by_type:
                by_type[v.violation_type] = []
            by_type[v.violation_type].append(v)
        
        for vtype, violations in sorted(by_type.items(), key=lambda x: len(x[1]), reverse=True):
            severity = max((v.severity for v in violations), 
                          key=lambda s: {"critical": 3, "high": 2, "medium": 1, "low": 0}[s])
            recommendations.append({
                "category": vtype,
                "severity": severity,
                "affected_flows": len(violations),
                "remediation": violations[0].remediation
            })
        
        return recommendations
    
    def _violation_to_dict(self, violation: DataFlowViolation) -> Dict[str, Any]:
        """Convert violation to dictionary."""
        return {
            "flow_id": violation.flow_id,
            "source": violation.source,
            "destination": violation.destination,
            "data_classification": violation.data_classification,
            "violation_type": violation.violation_type,
            "severity": violation.severity,
            "description": violation.description,
            "evidence": violation.evidence,
            "remediation": violation.remediation
        }
