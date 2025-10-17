"""Orchestrator Agent - Central coordinator for multi-agent compliance operations."""

import asyncio
import time
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

from .base_agent import BaseAgent, AgentTask, AgentStatus, AgentCapability
from ..core.bedrock_client import BedrockResponse
from ..utils.logger import get_logger
from ..utils.validators import validate_scan_request, validate_remediation_request

logger = get_logger(__name__)


class WorkflowStatus(Enum):
    """Workflow execution status."""
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ComplianceWorkflow:
    """Represents a compliance workflow."""
    
    workflow_id: str
    workflow_type: str
    target_resource: str
    compliance_frameworks: List[str]
    priority: int = 5
    created_at: float = field(default_factory=time.time)
    status: WorkflowStatus = WorkflowStatus.CREATED
    steps: List[Dict[str, Any]] = field(default_factory=list)
    results: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    total_violations: int = 0
    resolved_violations: int = 0
    risk_score: float = 0.0


@dataclass
class AgentAllocation:
    """Tracks agent allocations and load balancing."""
    
    agent_id: str
    agent_type: str
    capabilities: Set[str]
    current_load: int = 0
    max_capacity: int = 5
    response_time_avg: float = 0.0
    success_rate: float = 100.0
    last_used: float = field(default_factory=time.time)


class OrchestratorAgent(BaseAgent):
    """
    Orchestrator Agent coordinates all compliance operations.
    
    Responsibilities:
    - Workflow orchestration and management
    - Task delegation to specialized agents
    - Load balancing and resource allocation
    - Cross-agent communication coordination
    - Compliance pipeline optimization
    - Performance monitoring and optimization
    """
    
    def __init__(self, config: Dict[str, Any], **kwargs):
        """Initialize Orchestrator Agent."""
        super().__init__(
            agent_id="orchestrator-agent",
            config=config,
            **kwargs
        )
        
        # Workflow management
        self.active_workflows: Dict[str, ComplianceWorkflow] = {}
        self.workflow_queue: List[ComplianceWorkflow] = []
        
        # Agent registry and load balancing
        self.agent_registry: Dict[str, AgentAllocation] = {}
        self.capability_map: Dict[str, List[str]] = {}  # capability -> agent_ids
        
        # Performance optimization
        self.workflow_templates: Dict[str, List[Dict[str, Any]]] = {}
        self.optimization_metrics: Dict[str, float] = {}
        
        # Configuration
        self.max_concurrent_workflows = config.get("max_concurrent_workflows", 10)
        self.agent_discovery_interval = config.get("agent_discovery_interval", 60)
        
    def _initialize_capabilities(self) -> None:
        """Initialize orchestrator capabilities."""
        self.capabilities = {
            AgentCapability.ORCHESTRATION,
            AgentCapability.RISK_ASSESSMENT,
            AgentCapability.DATA_ANALYSIS
        }
        
        # Initialize workflow templates
        self._initialize_workflow_templates()
    
    def _initialize_workflow_templates(self) -> None:
        """Initialize pre-defined workflow templates."""
        
        # GDPR Compliance Workflow
        self.workflow_templates["gdpr_scan"] = [
            {
                "step": "compliance_scan",
                "agent_type": "compliance",
                "params": {
                    "framework": "gdpr",
                    "scan_type": "comprehensive"
                }
            },
            {
                "step": "audit_assessment",
                "agent_type": "audit",
                "params": {
                    "audit_type": "gdpr_readiness"
                }
            },
            {
                "step": "violation_remediation",
                "agent_type": "remediation",
                "params": {
                    "auto_remediate": True,
                    "approval_required": False
                }
            },
            {
                "step": "compliance_report",
                "agent_type": "audit",
                "params": {
                    "report_type": "gdpr_compliance"
                }
            }
        ]
        
        # HIPAA Compliance Workflow
        self.workflow_templates["hipaa_scan"] = [
            {
                "step": "compliance_scan",
                "agent_type": "compliance",
                "params": {
                    "framework": "hipaa",
                    "scan_type": "phi_focused"
                }
            },
            {
                "step": "audit_assessment",
                "agent_type": "audit",
                "params": {
                    "audit_type": "hipaa_security"
                }
            },
            {
                "step": "violation_remediation",
                "agent_type": "remediation",
                "params": {
                    "auto_remediate": False,  # HIPAA requires manual approval
                    "approval_required": True
                }
            }
        ]
        
        # PCI DSS Compliance Workflow
        self.workflow_templates["pci_scan"] = [
            {
                "step": "compliance_scan",
                "agent_type": "compliance",
                "params": {
                    "framework": "pci_dss",
                    "scan_type": "payment_focused"
                }
            },
            {
                "step": "audit_assessment",
                "agent_type": "audit",
                "params": {
                    "audit_type": "pci_requirements"
                }
            },
            {
                "step": "violation_remediation",
                "agent_type": "remediation",
                "params": {
                    "auto_remediate": True,
                    "approval_required": True
                }
            }
        ]
        
        # Emergency Response Workflow
        self.workflow_templates["incident_response"] = [
            {
                "step": "rapid_assessment",
                "agent_type": "compliance",
                "params": {
                    "scan_type": "incident_focused",
                    "priority": 1
                }
            },
            {
                "step": "immediate_containment",
                "agent_type": "remediation",
                "params": {
                    "emergency_mode": True,
                    "auto_remediate": True
                }
            },
            {
                "step": "incident_audit",
                "agent_type": "audit",
                "params": {
                    "audit_type": "incident_response"
                }
            },
            {
                "step": "explainability_analysis",
                "agent_type": "explainability",
                "params": {
                    "analysis_type": "incident_explanation"
                }
            }
        ]
    
    async def _execute_task(self, task: AgentTask) -> Dict[str, Any]:
        """Execute orchestrator-specific tasks."""
        task_type = task.task_type
        payload = task.payload
        
        try:
            if task_type == "create_workflow":
                return await self._create_workflow(payload)
            elif task_type == "execute_workflow":
                return await self._execute_workflow(payload)
            elif task_type == "get_workflow_status":
                return await self._get_workflow_status(payload)
            elif task_type == "cancel_workflow":
                return await self._cancel_workflow(payload)
            elif task_type == "optimize_workflows":
                return await self._optimize_workflows(payload)
            elif task_type == "agent_discovery":
                return await self._discover_agents()
            elif task_type == "load_balance":
                return await self._balance_agent_load(payload)
            elif task_type == "emergency_response":
                return await self._handle_emergency_response(payload)
            else:
                raise ValueError(f"Unknown task type: {task_type}")
                
        except Exception as e:
            logger.error(f"Failed to execute orchestrator task {task_type}: {e}")
            raise
    
    async def _create_workflow(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new compliance workflow."""
        try:
            workflow_type = payload["workflow_type"]
            target_resource = payload["target_resource"]
            compliance_frameworks = payload.get("compliance_frameworks", ["gdpr"])
            priority = payload.get("priority", 5)
            custom_steps = payload.get("custom_steps", [])
            
            # Generate workflow ID
            workflow_id = f"workflow_{int(time.time() * 1000)}"
            
            # Get workflow template or use custom steps
            if workflow_type in self.workflow_templates and not custom_steps:
                steps = self.workflow_templates[workflow_type].copy()
            else:
                steps = custom_steps
            
            # Create workflow
            workflow = ComplianceWorkflow(
                workflow_id=workflow_id,
                workflow_type=workflow_type,
                target_resource=target_resource,
                compliance_frameworks=compliance_frameworks,
                priority=priority,
                steps=steps
            )
            
            # Store workflow
            self.active_workflows[workflow_id] = workflow
            self.workflow_queue.append(workflow)
            
            # Sort queue by priority
            self.workflow_queue.sort(key=lambda w: w.priority)
            
            # Store in memory
            await self.store_memory(
                content={
                    "workflow_created": workflow_id,
                    "workflow_type": workflow_type,
                    "target_resource": target_resource,
                    "steps_count": len(steps)
                },
                memory_type="working",
                importance_score=0.8
            )
            
            # Send notification
            await self.broadcast_notification(
                notification_type="workflow_created",
                data={
                    "workflow_id": workflow_id,
                    "workflow_type": workflow_type,
                    "target_resource": target_resource
                }
            )
            
            logger.info(f"Created workflow {workflow_id} for {target_resource}")
            
            return {
                "workflow_id": workflow_id,
                "status": "created",
                "steps_count": len(steps),
                "estimated_duration": self._estimate_workflow_duration(steps)
            }
            
        except Exception as e:
            logger.error(f"Failed to create workflow: {e}")
            raise
    
    async def _execute_workflow(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a compliance workflow."""
        try:
            workflow_id = payload["workflow_id"]
            
            if workflow_id not in self.active_workflows:
                raise ValueError(f"Workflow {workflow_id} not found")
            
            workflow = self.active_workflows[workflow_id]
            workflow.status = WorkflowStatus.RUNNING
            
            logger.info(f"Executing workflow {workflow_id}")
            
            # Execute workflow steps
            for i, step in enumerate(workflow.steps):
                try:
                    step_result = await self._execute_workflow_step(workflow, step, i)
                    workflow.results[f"step_{i}"] = step_result
                    
                    # Update workflow metrics
                    if "violations_found" in step_result:
                        workflow.total_violations += step_result["violations_found"]
                    if "violations_resolved" in step_result:
                        workflow.resolved_violations += step_result["violations_resolved"]
                    if "risk_score" in step_result:
                        workflow.risk_score = max(workflow.risk_score, step_result["risk_score"])
                    
                except Exception as e:
                    logger.error(f"Workflow {workflow_id} step {i} failed: {e}")
                    workflow.status = WorkflowStatus.FAILED
                    workflow.error = str(e)
                    raise
            
            # Workflow completed successfully
            workflow.status = WorkflowStatus.COMPLETED
            
            # Generate final report using explainability agent
            final_report = await self._generate_workflow_report(workflow)
            workflow.results["final_report"] = final_report
            
            # Update metrics
            await self._update_workflow_metrics(workflow)
            
            # Store completion in memory
            await self.store_memory(
                content={
                    "workflow_completed": workflow_id,
                    "total_violations": workflow.total_violations,
                    "resolved_violations": workflow.resolved_violations,
                    "risk_score": workflow.risk_score,
                    "execution_time": time.time() - workflow.created_at
                },
                memory_type="working",
                importance_score=0.9
            )
            
            # Send completion notification
            await self.broadcast_notification(
                notification_type="workflow_completed",
                data={
                    "workflow_id": workflow_id,
                    "total_violations": workflow.total_violations,
                    "resolved_violations": workflow.resolved_violations,
                    "risk_score": workflow.risk_score
                }
            )
            
            logger.info(f"Workflow {workflow_id} completed successfully")
            
            return {
                "workflow_id": workflow_id,
                "status": "completed",
                "total_violations": workflow.total_violations,
                "resolved_violations": workflow.resolved_violations,
                "risk_score": workflow.risk_score,
                "execution_time": time.time() - workflow.created_at,
                "final_report": final_report
            }
            
        except Exception as e:
            logger.error(f"Failed to execute workflow: {e}")
            if workflow_id in self.active_workflows:
                self.active_workflows[workflow_id].status = WorkflowStatus.FAILED
                self.active_workflows[workflow_id].error = str(e)
            raise
    
    async def _execute_workflow_step(
        self,
        workflow: ComplianceWorkflow,
        step: Dict[str, Any],
        step_index: int
    ) -> Dict[str, Any]:
        """Execute a single workflow step."""
        try:
            step_name = step["step"]
            agent_type = step["agent_type"]
            params = step.get("params", {})
            
            logger.info(f"Executing step {step_index}: {step_name}")
            
            # Find best agent for this step
            agent_id = await self._select_best_agent(agent_type, step_name)
            
            if not agent_id:
                raise RuntimeError(f"No available agent for type {agent_type}")
            
            # Prepare task payload
            task_payload = {
                "workflow_id": workflow.workflow_id,
                "step_index": step_index,
                "target_resource": workflow.target_resource,
                "compliance_frameworks": workflow.compliance_frameworks,
                **params
            }
            
            # Execute step via agent
            result = await self.send_request(
                target_agent=agent_id,
                task_type=step_name,
                data=task_payload,
                timeout_seconds=params.get("timeout", 300)
            )
            
            # Update agent metrics
            await self._update_agent_metrics(agent_id, success=True)
            
            logger.info(f"Step {step_index} completed successfully")
            
            return result
            
        except Exception as e:
            # Update agent metrics on failure
            if 'agent_id' in locals():
                await self._update_agent_metrics(agent_id, success=False)
            
            logger.error(f"Step {step_index} failed: {e}")
            raise
    
    async def _select_best_agent(self, agent_type: str, capability: str) -> Optional[str]:
        """Select the best available agent for a task."""
        try:
            # Get agents with required capability
            capability_agents = self.capability_map.get(capability, [])
            
            if not capability_agents:
                # Discover agents if none found
                await self._discover_agents()
                capability_agents = self.capability_map.get(capability, [])
            
            if not capability_agents:
                return None
            
            # Filter by agent type and availability
            available_agents = []
            for agent_id in capability_agents:
                if agent_id in self.agent_registry:
                    allocation = self.agent_registry[agent_id]
                    if (allocation.agent_type == agent_type and 
                        allocation.current_load < allocation.max_capacity):
                        available_agents.append(allocation)
            
            if not available_agents:
                return None
            
            # Select best agent based on load and performance
            best_agent = min(
                available_agents,
                key=lambda a: (
                    a.current_load / a.max_capacity,  # Load factor
                    -a.success_rate,  # Success rate (negative for ascending)
                    a.response_time_avg  # Response time
                )
            )
            
            # Update load
            best_agent.current_load += 1
            best_agent.last_used = time.time()
            
            return best_agent.agent_id
            
        except Exception as e:
            logger.error(f"Failed to select best agent: {e}")
            return None
    
    async def _discover_agents(self) -> Dict[str, Any]:
        """Discover available agents and their capabilities."""
        try:
            # Get registered agents from gateway
            registered_agents = await self.gateway.get_registered_agents()
            
            new_agents = 0
            updated_capabilities = 0
            
            for agent_info in registered_agents:
                agent_id = agent_info["agent_id"]
                capabilities = agent_info.get("capabilities", [])
                metadata = agent_info.get("metadata", {})
                
                # Update agent registry
                if agent_id not in self.agent_registry:
                    self.agent_registry[agent_id] = AgentAllocation(
                        agent_id=agent_id,
                        agent_type=metadata.get("agent_type", "unknown"),
                        capabilities=set(capabilities)
                    )
                    new_agents += 1
                else:
                    # Update capabilities
                    old_caps = self.agent_registry[agent_id].capabilities
                    new_caps = set(capabilities)
                    if old_caps != new_caps:
                        self.agent_registry[agent_id].capabilities = new_caps
                        updated_capabilities += 1
                
                # Update capability map
                for capability in capabilities:
                    if capability not in self.capability_map:
                        self.capability_map[capability] = []
                    if agent_id not in self.capability_map[capability]:
                        self.capability_map[capability].append(agent_id)
            
            logger.info(f"Agent discovery completed: {new_agents} new, {updated_capabilities} updated")
            
            return {
                "total_agents": len(self.agent_registry),
                "new_agents": new_agents,
                "updated_capabilities": updated_capabilities,
                "capability_map": {k: len(v) for k, v in self.capability_map.items()}
            }
            
        except Exception as e:
            logger.error(f"Agent discovery failed: {e}")
            raise
    
    async def _update_agent_metrics(self, agent_id: str, success: bool, response_time: float = 0) -> None:
        """Update agent performance metrics."""
        try:
            if agent_id in self.agent_registry:
                allocation = self.agent_registry[agent_id]
                
                # Update load
                allocation.current_load = max(0, allocation.current_load - 1)
                
                # Update success rate (exponential moving average)
                alpha = 0.1
                current_success = 100.0 if success else 0.0
                allocation.success_rate = (
                    alpha * current_success + 
                    (1 - alpha) * allocation.success_rate
                )
                
                # Update response time (exponential moving average)
                if response_time > 0:
                    allocation.response_time_avg = (
                        alpha * response_time + 
                        (1 - alpha) * allocation.response_time_avg
                    )
                
        except Exception as e:
            logger.error(f"Failed to update agent metrics: {e}")
    
    async def _generate_workflow_report(self, workflow: ComplianceWorkflow) -> Dict[str, Any]:
        """Generate comprehensive workflow report using explainability agent."""
        try:
            # Request explainability analysis
            report_data = await self.send_request(
                target_agent="explainability-agent",
                task_type="workflow_explanation",
                data={
                    "workflow_id": workflow.workflow_id,
                    "workflow_type": workflow.workflow_type,
                    "target_resource": workflow.target_resource,
                    "compliance_frameworks": workflow.compliance_frameworks,
                    "results": workflow.results,
                    "total_violations": workflow.total_violations,
                    "resolved_violations": workflow.resolved_violations,
                    "risk_score": workflow.risk_score
                }
            )
            
            return report_data
            
        except Exception as e:
            logger.error(f"Failed to generate workflow report: {e}")
            return {
                "error": f"Report generation failed: {e}",
                "basic_summary": {
                    "workflow_id": workflow.workflow_id,
                    "status": workflow.status.value,
                    "total_violations": workflow.total_violations,
                    "resolved_violations": workflow.resolved_violations,
                    "risk_score": workflow.risk_score
                }
            }
    
    async def _get_workflow_status(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Get status of a workflow."""
        workflow_id = payload["workflow_id"]
        
        if workflow_id not in self.active_workflows:
            raise ValueError(f"Workflow {workflow_id} not found")
        
        workflow = self.active_workflows[workflow_id]
        
        return {
            "workflow_id": workflow_id,
            "status": workflow.status.value,
            "progress": len(workflow.results) / max(len(workflow.steps), 1) * 100,
            "total_violations": workflow.total_violations,
            "resolved_violations": workflow.resolved_violations,
            "risk_score": workflow.risk_score,
            "created_at": workflow.created_at,
            "error": workflow.error
        }
    
    async def _cancel_workflow(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Cancel a running workflow."""
        workflow_id = payload["workflow_id"]
        
        if workflow_id not in self.active_workflows:
            raise ValueError(f"Workflow {workflow_id} not found")
        
        workflow = self.active_workflows[workflow_id]
        workflow.status = WorkflowStatus.CANCELLED
        
        # Remove from queue if not started
        self.workflow_queue = [w for w in self.workflow_queue if w.workflow_id != workflow_id]
        
        logger.info(f"Workflow {workflow_id} cancelled")
        
        return {
            "workflow_id": workflow_id,
            "status": "cancelled"
        }
    
    async def _optimize_workflows(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize workflow performance using AI analysis."""
        try:
            # Analyze workflow performance data
            performance_data = {
                "total_workflows": len(self.active_workflows),
                "completed_workflows": len([w for w in self.active_workflows.values() 
                                          if w.status == WorkflowStatus.COMPLETED]),
                "average_execution_time": sum([
                    time.time() - w.created_at for w in self.active_workflows.values()
                    if w.status == WorkflowStatus.COMPLETED
                ]) / max(1, len([w for w in self.active_workflows.values() 
                               if w.status == WorkflowStatus.COMPLETED])),
                "agent_utilization": {
                    agent_id: allocation.current_load / allocation.max_capacity
                    for agent_id, allocation in self.agent_registry.items()
                }
            }
            
            # Use LLM to analyze and suggest optimizations
            optimization_prompt = f"""
            Analyze the following workflow performance data and suggest optimizations:
            
            Performance Data:
            {performance_data}
            
            Current Workflow Templates:
            {list(self.workflow_templates.keys())}
            
            Please provide:
            1. Performance bottlenecks identified
            2. Load balancing recommendations
            3. Workflow optimization suggestions
            4. Resource allocation improvements
            """
            
            response = await self.invoke_llm(
                prompt=optimization_prompt,
                system_prompt="You are an expert in workflow optimization and load balancing."
            )
            
            optimization_suggestions = response.content
            
            # Store optimization results
            await self.store_memory(
                content={
                    "optimization_analysis": optimization_suggestions,
                    "performance_data": performance_data,
                    "timestamp": time.time()
                },
                memory_type="context",
                importance_score=0.7
            )
            
            return {
                "optimization_suggestions": optimization_suggestions,
                "performance_data": performance_data,
                "status": "completed"
            }
            
        except Exception as e:
            logger.error(f"Workflow optimization failed: {e}")
            raise
    
    async def _handle_emergency_response(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle emergency compliance incidents."""
        try:
            incident_type = payload["incident_type"]
            target_resource = payload["target_resource"]
            severity = payload.get("severity", "high")
            
            logger.warning(f"Emergency response triggered: {incident_type} on {target_resource}")
            
            # Create high-priority emergency workflow
            emergency_workflow = await self._create_workflow({
                "workflow_type": "incident_response",
                "target_resource": target_resource,
                "compliance_frameworks": payload.get("frameworks", ["gdpr", "hipaa"]),
                "priority": 1,  # Highest priority
                "custom_steps": self.workflow_templates["incident_response"]
            })
            
            # Execute immediately
            execution_result = await self._execute_workflow({
                "workflow_id": emergency_workflow["workflow_id"]
            })
            
            # Send emergency notifications
            await self.broadcast_notification(
                notification_type="emergency_response",
                data={
                    "incident_type": incident_type,
                    "target_resource": target_resource,
                    "severity": severity,
                    "workflow_id": emergency_workflow["workflow_id"],
                    "immediate_actions": execution_result.get("immediate_actions", [])
                }
            )
            
            return {
                "emergency_response": "activated",
                "workflow_id": emergency_workflow["workflow_id"],
                "immediate_actions": execution_result.get("immediate_actions", []),
                "risk_score": execution_result.get("risk_score", 0),
                "status": "completed"
            }
            
        except Exception as e:
            logger.error(f"Emergency response failed: {e}")
            raise
    
    def _estimate_workflow_duration(self, steps: List[Dict[str, Any]]) -> float:
        """Estimate workflow execution duration."""
        # Base estimates for different step types (in seconds)
        step_estimates = {
            "compliance_scan": 60,
            "audit_assessment": 45,
            "violation_remediation": 90,
            "compliance_report": 30,
            "rapid_assessment": 30,
            "immediate_containment": 45,
            "incident_audit": 60,
            "explainability_analysis": 40
        }
        
        total_estimate = 0
        for step in steps:
            step_name = step.get("step", "unknown")
            base_time = step_estimates.get(step_name, 60)
            
            # Adjust for complexity
            complexity_multiplier = step.get("params", {}).get("complexity_multiplier", 1.0)
            total_estimate += base_time * complexity_multiplier
        
        return total_estimate
    
    async def _update_workflow_metrics(self, workflow: ComplianceWorkflow) -> None:
        """Update optimization metrics based on workflow completion."""
        try:
            execution_time = time.time() - workflow.created_at
            resolution_rate = (workflow.resolved_violations / 
                             max(workflow.total_violations, 1)) * 100
            
            # Update metrics for optimization
            workflow_type = workflow.workflow_type
            if workflow_type not in self.optimization_metrics:
                self.optimization_metrics[workflow_type] = {
                    "avg_execution_time": execution_time,
                    "avg_resolution_rate": resolution_rate,
                    "completion_count": 1
                }
            else:
                metrics = self.optimization_metrics[workflow_type]
                alpha = 0.2  # Exponential moving average factor
                
                metrics["avg_execution_time"] = (
                    alpha * execution_time + 
                    (1 - alpha) * metrics["avg_execution_time"]
                )
                metrics["avg_resolution_rate"] = (
                    alpha * resolution_rate + 
                    (1 - alpha) * metrics["avg_resolution_rate"]
                )
                metrics["completion_count"] += 1
            
        except Exception as e:
            logger.error(f"Failed to update workflow metrics: {e}")
    
    async def _balance_agent_load(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Perform load balancing across agents."""
        try:
            # Analyze current load distribution
            total_load = sum(allocation.current_load for allocation in self.agent_registry.values())
            agent_count = len(self.agent_registry)
            
            if agent_count == 0:
                return {"status": "no_agents", "message": "No agents available for load balancing"}
            
            average_load = total_load / agent_count
            
            overloaded_agents = [
                allocation for allocation in self.agent_registry.values()
                if allocation.current_load > average_load * 1.5
            ]
            
            underloaded_agents = [
                allocation for allocation in self.agent_registry.values()
                if allocation.current_load < average_load * 0.5
            ]
            
            # Generate load balancing recommendations
            recommendations = []
            
            if overloaded_agents:
                recommendations.append({
                    "type": "scale_out",
                    "agents": [a.agent_id for a in overloaded_agents],
                    "recommendation": "Consider scaling out these agents or redistributing load"
                })
            
            if underloaded_agents:
                recommendations.append({
                    "type": "optimize_allocation",
                    "agents": [a.agent_id for a in underloaded_agents],
                    "recommendation": "These agents have spare capacity for additional tasks"
                })
            
            return {
                "status": "completed",
                "total_load": total_load,
                "average_load": average_load,
                "overloaded_agents": len(overloaded_agents),
                "underloaded_agents": len(underloaded_agents),
                "recommendations": recommendations
            }
            
        except Exception as e:
            logger.error(f"Load balancing failed: {e}")
            raise