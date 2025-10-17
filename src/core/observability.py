"""Observability and monitoring using AWS Bedrock AgentCore Observability."""

import json
import time
import uuid
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, field
from enum import Enum
import asyncio

import boto3
from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry, generate_latest
import structlog

from ..utils.config import get_config
from ..utils.logger import get_logger

logger = get_logger(__name__)


class MetricType(Enum):
    """Types of metrics that can be recorded."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


class LogLevel(Enum):
    """Log levels for events."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class MetricEntry:
    """Represents a metric entry."""
    
    metric_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    metric_name: str = ""
    metric_type: MetricType = MetricType.COUNTER
    value: float = 0.0
    labels: Dict[str, str] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LogEntry:
    """Represents a log entry."""
    
    log_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    level: LogLevel = LogLevel.INFO
    message: str = ""
    agent_id: Optional[str] = None
    component: Optional[str] = None
    task_id: Optional[str] = None
    session_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    structured_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TraceEntry:
    """Represents a distributed trace entry."""
    
    trace_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    span_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    parent_span_id: Optional[str] = None
    operation_name: str = ""
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    duration_ms: Optional[float] = None
    agent_id: Optional[str] = None
    status: str = "started"  # started, completed, failed
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: Dict[str, str] = field(default_factory=dict)


class ObservabilityConfig:
    """Configuration for observability system."""
    
    def __init__(self):
        config = get_config()
        
        self.enable_metrics = config.get("observability.enable_metrics", True)
        self.enable_logging = config.get("observability.enable_logging", True)
        self.enable_tracing = config.get("observability.enable_tracing", True)
        self.metrics_port = config.get("observability.metrics_port", 8080)
        self.log_level = config.get("observability.log_level", "INFO")
        self.cloudwatch_namespace = config.get("observability.cloudwatch_namespace", "ComplianceGuardian")
        self.retention_days = config.get("observability.retention_days", 30)
        self.enable_prometheus = config.get("observability.enable_prometheus", True)
        self.enable_cloudwatch = config.get("observability.enable_cloudwatch", True)


class ObservabilityManager:
    """
    Observability and monitoring using AWS Bedrock AgentCore Observability.
    
    Provides:
    - Metrics collection and reporting (Prometheus + CloudWatch)
    - Structured logging with correlation IDs
    - Distributed tracing across agents
    - Performance monitoring
    - Health checks and alerting
    - Cost tracking and optimization
    """
    
    def __init__(self, config: Optional[ObservabilityConfig] = None):
        self.config = config or ObservabilityConfig()
        
        # Metrics
        self._prometheus_registry = CollectorRegistry()
        self._metrics: Dict[str, Any] = {}
        self._metric_history: List[MetricEntry] = []
        
        # Logging
        self._log_entries: List[LogEntry] = []
        self._structured_logger = structlog.get_logger()
        
        # Tracing
        self._active_traces: Dict[str, TraceEntry] = {}
        self._completed_traces: List[TraceEntry] = []
        
        # AWS clients
        self._cloudwatch_client = None
        self._logs_client = None
        self._xray_client = None
        
        self._initialize_metrics()
    
    def _initialize_metrics(self) -> None:
        """Initialize Prometheus metrics."""
        if not self.config.enable_prometheus:
            return
        
        # Agent performance metrics
        self._metrics["agent_task_total"] = Counter(
            "agent_task_total",
            "Total number of agent tasks",
            ["agent_id", "task_type", "status"],
            registry=self._prometheus_registry
        )
        
        self._metrics["agent_task_duration"] = Histogram(
            "agent_task_duration_seconds",
            "Agent task duration in seconds",
            ["agent_id", "task_type"],
            registry=self._prometheus_registry
        )
        
        self._metrics["agent_memory_usage"] = Gauge(
            "agent_memory_usage_mb",
            "Agent memory usage in MB",
            ["agent_id"],
            registry=self._prometheus_registry
        )
        
        # Bedrock metrics
        self._metrics["bedrock_requests_total"] = Counter(
            "bedrock_requests_total",
            "Total Bedrock API requests",
            ["model_id", "agent_id", "status"],
            registry=self._prometheus_registry
        )
        
        self._metrics["bedrock_tokens_total"] = Counter(
            "bedrock_tokens_total",
            "Total tokens used",
            ["model_id", "agent_id", "token_type"],
            registry=self._prometheus_registry
        )
        
        self._metrics["bedrock_request_duration"] = Histogram(
            "bedrock_request_duration_seconds",
            "Bedrock request duration",
            ["model_id", "agent_id"],
            registry=self._prometheus_registry
        )
        
        # Compliance metrics
        self._metrics["violations_detected_total"] = Counter(
            "violations_detected_total",
            "Total compliance violations detected",
            ["framework", "severity", "agent_id"],
            registry=self._prometheus_registry
        )
        
        self._metrics["remediations_applied_total"] = Counter(
            "remediations_applied_total",
            "Total remediations applied",
            ["remediation_type", "status"],
            registry=self._prometheus_registry
        )
        
        # System metrics
        self._metrics["active_agents"] = Gauge(
            "active_agents",
            "Number of active agents",
            registry=self._prometheus_registry
        )
        
        self._metrics["queue_size"] = Gauge(
            "queue_size",
            "Task queue size",
            ["queue_type"],
            registry=self._prometheus_registry
        )
    
    async def initialize(self) -> None:
        """Initialize observability system and AWS services."""
        try:
            # Initialize AWS clients
            if self.config.enable_cloudwatch:
                self._cloudwatch_client = boto3.client("cloudwatch")
                self._logs_client = boto3.client("logs")
            
            if self.config.enable_tracing:
                self._xray_client = boto3.client("xray")
            
            # Create CloudWatch log group
            if self.config.enable_cloudwatch:
                await self._create_log_group()
            
            logger.info("Observability manager initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize observability manager: {e}")
            raise
    
    async def _create_log_group(self) -> None:
        """Create CloudWatch log group if it doesn't exist."""
        try:
            log_group_name = f"/aws/compliance-guardian/{self.config.cloudwatch_namespace}"
            
            try:
                self._logs_client.create_log_group(
                    logGroupName=log_group_name,
                    retentionInDays=self.config.retention_days
                )
            except self._logs_client.exceptions.ResourceAlreadyExistsException:
                pass  # Log group already exists
            
        except Exception as e:
            logger.warning(f"Failed to create log group: {e}")
    
    async def record_agent_task_start(
        self,
        agent_id: str,
        task_id: str,
        task_type: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Record the start of an agent task."""
        try:
            # Create trace
            trace_id = str(uuid.uuid4())
            trace = TraceEntry(
                trace_id=trace_id,
                operation_name=f"agent_task_{task_type}",
                agent_id=agent_id,
                metadata=metadata or {},
                tags={
                    "agent_id": agent_id,
                    "task_id": task_id,
                    "task_type": task_type
                }
            )
            
            self._active_traces[trace_id] = trace
            
            # Log event
            await self.log_event(
                level=LogLevel.INFO,
                message=f"Agent task started: {task_type}",
                agent_id=agent_id,
                task_id=task_id,
                metadata=metadata
            )
            
            # Record metric
            if self.config.enable_metrics:
                self._metrics["agent_task_total"].labels(
                    agent_id=agent_id,
                    task_type=task_type,
                    status="started"
                ).inc()
            
            return trace_id
            
        except Exception as e:
            logger.error(f"Failed to record agent task start: {e}")
            return ""
    
    async def record_agent_task_completion(
        self,
        agent_id: str,
        task_id: str,
        result: Dict[str, Any],
        duration: float,
        trace_id: Optional[str] = None
    ) -> None:
        """Record the completion of an agent task."""
        try:
            # Update trace
            if trace_id and trace_id in self._active_traces:
                trace = self._active_traces[trace_id]
                trace.end_time = time.time()
                trace.duration_ms = duration * 1000
                trace.status = "completed"
                trace.metadata.update({"result": result})
                
                # Move to completed traces
                self._completed_traces.append(trace)
                del self._active_traces[trace_id]
            
            # Log event
            await self.log_event(
                level=LogLevel.INFO,
                message=f"Agent task completed successfully",
                agent_id=agent_id,
                task_id=task_id,
                metadata={
                    "duration_seconds": duration,
                    "result_summary": str(result)[:100]  # Truncate for logging
                }
            )
            
            # Record metrics
            if self.config.enable_metrics:
                task_type = result.get("task_type", "unknown")
                
                self._metrics["agent_task_total"].labels(
                    agent_id=agent_id,
                    task_type=task_type,
                    status="completed"
                ).inc()
                
                self._metrics["agent_task_duration"].labels(
                    agent_id=agent_id,
                    task_type=task_type
                ).observe(duration)
            
        except Exception as e:
            logger.error(f"Failed to record agent task completion: {e}")
    
    async def record_agent_task_failure(
        self,
        agent_id: str,
        task_id: str,
        error: str,
        trace_id: Optional[str] = None
    ) -> None:
        """Record the failure of an agent task."""
        try:
            # Update trace
            if trace_id and trace_id in self._active_traces:
                trace = self._active_traces[trace_id]
                trace.end_time = time.time()
                trace.duration_ms = (trace.end_time - trace.start_time) * 1000
                trace.status = "failed"
                trace.metadata.update({"error": error})
                
                # Move to completed traces
                self._completed_traces.append(trace)
                del self._active_traces[trace_id]
            
            # Log event
            await self.log_event(
                level=LogLevel.ERROR,
                message=f"Agent task failed: {error}",
                agent_id=agent_id,
                task_id=task_id,
                metadata={"error": error}
            )
            
            # Record metric
            if self.config.enable_metrics:
                self._metrics["agent_task_total"].labels(
                    agent_id=agent_id,
                    task_type="unknown",
                    status="failed"
                ).inc()
            
        except Exception as e:
            logger.error(f"Failed to record agent task failure: {e}")
    
    async def record_bedrock_request(
        self,
        model_id: str,
        agent_id: str,
        duration: float,
        input_tokens: int,
        output_tokens: int,
        status: str = "success"
    ) -> None:
        """Record a Bedrock API request."""
        try:
            # Record metrics
            if self.config.enable_metrics:
                self._metrics["bedrock_requests_total"].labels(
                    model_id=model_id,
                    agent_id=agent_id,
                    status=status
                ).inc()
                
                self._metrics["bedrock_tokens_total"].labels(
                    model_id=model_id,
                    agent_id=agent_id,
                    token_type="input"
                ).inc(input_tokens)
                
                self._metrics["bedrock_tokens_total"].labels(
                    model_id=model_id,
                    agent_id=agent_id,
                    token_type="output"
                ).inc(output_tokens)
                
                self._metrics["bedrock_request_duration"].labels(
                    model_id=model_id,
                    agent_id=agent_id
                ).observe(duration)
            
            # Log event
            await self.log_event(
                level=LogLevel.INFO,
                message=f"Bedrock request completed",
                agent_id=agent_id,
                metadata={
                    "model_id": model_id,
                    "duration": duration,
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "status": status
                }
            )
            
            # Send to CloudWatch
            if self.config.enable_cloudwatch:
                await self._send_cloudwatch_metrics([
                    {
                        "MetricName": "BedrockRequests",
                        "Value": 1,
                        "Unit": "Count",
                        "Dimensions": [
                            {"Name": "ModelId", "Value": model_id},
                            {"Name": "AgentId", "Value": agent_id},
                            {"Name": "Status", "Value": status}
                        ]
                    },
                    {
                        "MetricName": "BedrockTokens",
                        "Value": input_tokens + output_tokens,
                        "Unit": "Count",
                        "Dimensions": [
                            {"Name": "ModelId", "Value": model_id},
                            {"Name": "AgentId", "Value": agent_id}
                        ]
                    }
                ])
            
        except Exception as e:
            logger.error(f"Failed to record Bedrock request: {e}")
    
    async def record_compliance_violation(
        self,
        framework: str,
        severity: str,
        agent_id: str,
        violation_details: Dict[str, Any]
    ) -> None:
        """Record a compliance violation detection."""
        try:
            # Record metric
            if self.config.enable_metrics:
                self._metrics["violations_detected_total"].labels(
                    framework=framework,
                    severity=severity,
                    agent_id=agent_id
                ).inc()
            
            # Log event
            await self.log_event(
                level=LogLevel.WARNING if severity in ["HIGH", "CRITICAL"] else LogLevel.INFO,
                message=f"Compliance violation detected: {framework} {severity}",
                agent_id=agent_id,
                metadata={
                    "framework": framework,
                    "severity": severity,
                    "violation_details": violation_details
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to record compliance violation: {e}")
    
    async def record_remediation(
        self,
        remediation_type: str,
        status: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Record a remediation action."""
        try:
            # Record metric
            if self.config.enable_metrics:
                self._metrics["remediations_applied_total"].labels(
                    remediation_type=remediation_type,
                    status=status
                ).inc()
            
            # Log event
            await self.log_event(
                level=LogLevel.INFO,
                message=f"Remediation applied: {remediation_type} ({status})",
                metadata={
                    "remediation_type": remediation_type,
                    "status": status,
                    **(metadata or {})
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to record remediation: {e}")
    
    async def log_event(
        self,
        level: LogLevel,
        message: str,
        agent_id: Optional[str] = None,
        component: Optional[str] = None,
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log an event with structured data."""
        try:
            log_entry = LogEntry(
                level=level,
                message=message,
                agent_id=agent_id,
                component=component,
                task_id=task_id,
                session_id=session_id,
                metadata=metadata or {}
            )
            
            self._log_entries.append(log_entry)
            
            # Log to standard logger
            log_data = {
                "agent_id": agent_id,
                "component": component,
                "task_id": task_id,
                "session_id": session_id,
                **(metadata or {})
            }
            
            if level == LogLevel.DEBUG:
                self._structured_logger.debug(message, **log_data)
            elif level == LogLevel.INFO:
                self._structured_logger.info(message, **log_data)
            elif level == LogLevel.WARNING:
                self._structured_logger.warning(message, **log_data)
            elif level == LogLevel.ERROR:
                self._structured_logger.error(message, **log_data)
            elif level == LogLevel.CRITICAL:
                self._structured_logger.critical(message, **log_data)
            
            # Send to CloudWatch if enabled
            if self.config.enable_cloudwatch:
                await self._send_cloudwatch_log(log_entry)
            
        except Exception as e:
            # Avoid logging recursion
            print(f"Failed to log event: {e}")
    
    async def _send_cloudwatch_log(self, log_entry: LogEntry) -> None:
        """Send log entry to CloudWatch."""
        try:
            log_group_name = f"/aws/compliance-guardian/{self.config.cloudwatch_namespace}"
            log_stream_name = f"agent-logs-{time.strftime('%Y-%m-%d')}"
            
            # Create log stream if it doesn't exist
            try:
                self._logs_client.create_log_stream(
                    logGroupName=log_group_name,
                    logStreamName=log_stream_name
                )
            except self._logs_client.exceptions.ResourceAlreadyExistsException:
                pass
            
            # Prepare log event
            log_event = {
                "timestamp": int(log_entry.timestamp * 1000),
                "message": json.dumps({
                    "level": log_entry.level.value,
                    "message": log_entry.message,
                    "agent_id": log_entry.agent_id,
                    "component": log_entry.component,
                    "task_id": log_entry.task_id,
                    "session_id": log_entry.session_id,
                    "metadata": log_entry.metadata
                })
            }
            
            # Send to CloudWatch
            self._logs_client.put_log_events(
                logGroupName=log_group_name,
                logStreamName=log_stream_name,
                logEvents=[log_event]
            )
            
        except Exception as e:
            # Avoid logging recursion
            print(f"Failed to send CloudWatch log: {e}")
    
    async def _send_cloudwatch_metrics(self, metrics: List[Dict[str, Any]]) -> None:
        """Send metrics to CloudWatch."""
        try:
            metric_data = []
            
            for metric in metrics:
                metric_data.append({
                    "MetricName": metric["MetricName"],
                    "Value": metric["Value"],
                    "Unit": metric.get("Unit", "Count"),
                    "Timestamp": time.time(),
                    "Dimensions": metric.get("Dimensions", [])
                })
            
            # Send to CloudWatch in batches of 20 (AWS limit)
            for i in range(0, len(metric_data), 20):
                batch = metric_data[i:i+20]
                self._cloudwatch_client.put_metric_data(
                    Namespace=self.config.cloudwatch_namespace,
                    MetricData=batch
                )
            
        except Exception as e:
            logger.error(f"Failed to send CloudWatch metrics: {e}")
    
    async def update_agent_status(self, agent_id: str, status: str) -> None:
        """Update agent status metrics."""
        try:
            if self.config.enable_metrics:
                # This would typically update a gauge metric
                pass
            
            await self.log_event(
                level=LogLevel.INFO,
                message=f"Agent status updated: {status}",
                agent_id=agent_id,
                metadata={"status": status}
            )
            
        except Exception as e:
            logger.error(f"Failed to update agent status: {e}")
    
    def get_prometheus_metrics(self) -> str:
        """Get Prometheus metrics in text format."""
        try:
            return generate_latest(self._prometheus_registry).decode('utf-8')
        except Exception as e:
            logger.error(f"Failed to generate Prometheus metrics: {e}")
            return ""
    
    def get_observability_metrics(self) -> Dict[str, Any]:
        """Get observability system metrics."""
        return {
            "total_log_entries": len(self._log_entries),
            "active_traces": len(self._active_traces),
            "completed_traces": len(self._completed_traces),
            "metric_history_size": len(self._metric_history),
            "config": {
                "enable_metrics": self.config.enable_metrics,
                "enable_logging": self.config.enable_logging,
                "enable_tracing": self.config.enable_tracing,
                "enable_cloudwatch": self.config.enable_cloudwatch
            }
        }
    
    async def cleanup_old_data(self, retention_hours: int = 24) -> int:
        """Clean up old observability data."""
        try:
            cutoff_time = time.time() - (retention_hours * 3600)
            cleaned_count = 0
            
            # Clean old log entries
            original_log_count = len(self._log_entries)
            self._log_entries = [
                entry for entry in self._log_entries
                if entry.timestamp > cutoff_time
            ]
            cleaned_count += original_log_count - len(self._log_entries)
            
            # Clean old completed traces
            original_trace_count = len(self._completed_traces)
            self._completed_traces = [
                trace for trace in self._completed_traces
                if trace.start_time > cutoff_time
            ]
            cleaned_count += original_trace_count - len(self._completed_traces)
            
            # Clean old metric history
            original_metric_count = len(self._metric_history)
            self._metric_history = [
                metric for metric in self._metric_history
                if metric.timestamp > cutoff_time
            ]
            cleaned_count += original_metric_count - len(self._metric_history)
            
            if cleaned_count > 0:
                await self.log_event(
                    level=LogLevel.INFO,
                    message=f"Cleaned up {cleaned_count} old observability records"
                )
            
            return cleaned_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup old data: {e}")
            return 0
    
    def health_check(self) -> Dict[str, Any]:
        """Perform health check on observability system."""
        try:
            # Test CloudWatch connectivity
            cloudwatch_healthy = True
            if self.config.enable_cloudwatch:
                try:
                    self._cloudwatch_client.list_metrics(MaxRecords=1)
                except Exception:
                    cloudwatch_healthy = False
            
            # Check data sizes
            warnings = []
            if len(self._log_entries) > 10000:
                warnings.append("Large number of log entries")
            if len(self._active_traces) > 1000:
                warnings.append("Large number of active traces")
            
            status = "healthy"
            if warnings:
                status = "degraded"
            if not cloudwatch_healthy and self.config.enable_cloudwatch:
                status = "unhealthy"
            
            return {
                "status": status,
                "cloudwatch_healthy": cloudwatch_healthy,
                "metrics": self.get_observability_metrics(),
                "warnings": warnings
            }
            
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e)
            }