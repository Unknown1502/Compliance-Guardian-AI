"""Policy injection and enforcement system."""

import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum

import boto3
from botocore.exceptions import ClientError

from ..utils.logger import get_logger

logger = get_logger(__name__)


class PolicyType(Enum):
    """Policy types."""
    IAM = "iam"
    S3_BUCKET = "s3_bucket"
    KMS = "kms"
    SCP = "scp"
    RESOURCE = "resource"


@dataclass
class PolicyInjectionResult:
    """Result of policy injection."""
    
    resource_id: str
    policy_type: str
    action: str
    status: str
    policy_arn: Optional[str] = None
    error: Optional[str] = None


class PolicyInjector:
    """
    Automated policy injection and enforcement system.
    
    Injects compliance policies:
    - IAM policies for least privilege
    - S3 bucket policies for access control
    - KMS key policies for encryption
    - SCPs for organization-wide controls
    - Resource-based policies
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize policy injector."""
        self.config = config or {}
        
        # AWS clients
        self.iam_client = boto3.client('iam')
        self.s3_client = boto3.client('s3')
        self.kms_client = boto3.client('kms')
        self.organizations_client = boto3.client('organizations')
        
        # Policy templates
        self._init_policy_templates()
    
    def _init_policy_templates(self) -> None:
        """Initialize compliance policy templates."""
        # GDPR data access policy
        self.gdpr_data_access_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "GDPRDataAccess",
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:ListBucket"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "aws:RequestedRegion": ["eu-west-1", "eu-central-1"]
                        }
                    }
                },
                {
                    "Sid": "RequireEncryption",
                    "Effect": "Deny",
                    "Action": "s3:PutObject",
                    "Resource": "*",
                    "Condition": {
                        "StringNotEquals": {
                            "s3:x-amz-server-side-encryption": "aws:kms"
                        }
                    }
                }
            ]
        }
        
        # PCI DSS encryption enforcement
        self.pci_encryption_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "RequireEncryptionInTransit",
                    "Effect": "Deny",
                    "Action": "s3:*",
                    "Resource": "*",
                    "Condition": {
                        "Bool": {
                            "aws:SecureTransport": "false"
                        }
                    }
                },
                {
                    "Sid": "RequireEncryptionAtRest",
                    "Effect": "Deny",
                    "Action": "s3:PutObject",
                    "Resource": "*",
                    "Condition": {
                        "StringNotEquals": {
                            "s3:x-amz-server-side-encryption": "aws:kms"
                        }
                    }
                }
            ]
        }
        
        # HIPAA access control
        self.hipaa_access_control_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "RequireMFA",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {
                        "BoolIfExists": {
                            "aws:MultiFactorAuthPresent": "false"
                        }
                    }
                },
                {
                    "Sid": "RestrictPHIAccess",
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:PutObject"
                    ],
                    "Resource": "arn:aws:s3:::*-phi-*/*",
                    "Condition": {
                        "StringLike": {
                            "aws:userid": "*-authorized-*"
                        }
                    }
                }
            ]
        }
    
    async def inject_iam_policy(
        self,
        policy_name: str,
        policy_document: Dict[str, Any],
        description: Optional[str] = None
    ) -> PolicyInjectionResult:
        """Inject IAM policy."""
        try:
            # Create policy
            response = self.iam_client.create_policy(
                PolicyName=policy_name,
                PolicyDocument=json.dumps(policy_document),
                Description=description or f"Compliance policy: {policy_name}"
            )
            
            policy_arn = response['Policy']['Arn']
            
            logger.info(f"Created IAM policy {policy_name}: {policy_arn}")
            
            return PolicyInjectionResult(
                resource_id=policy_name,
                policy_type=PolicyType.IAM.value,
                action="create",
                status="success",
                policy_arn=policy_arn
            )
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'EntityAlreadyExists':
                # Policy exists, update it
                return await self._update_iam_policy(policy_name, policy_document)
            else:
                logger.error(f"Failed to inject IAM policy {policy_name}: {e}")
                return PolicyInjectionResult(
                    resource_id=policy_name,
                    policy_type=PolicyType.IAM.value,
                    action="create",
                    status="failed",
                    error=str(e)
                )
    
    async def _update_iam_policy(self, policy_name: str, policy_document: Dict[str, Any]) -> PolicyInjectionResult:
        """Update existing IAM policy."""
        try:
            # Get policy ARN
            account_id = boto3.client('sts').get_caller_identity()['Account']
            policy_arn = f"arn:aws:iam::{account_id}:policy/{policy_name}"
            
            # Create new version
            self.iam_client.create_policy_version(
                PolicyArn=policy_arn,
                PolicyDocument=json.dumps(policy_document),
                SetAsDefault=True
            )
            
            logger.info(f"Updated IAM policy {policy_name}")
            
            return PolicyInjectionResult(
                resource_id=policy_name,
                policy_type=PolicyType.IAM.value,
                action="update",
                status="success",
                policy_arn=policy_arn
            )
            
        except Exception as e:
            logger.error(f"Failed to update IAM policy {policy_name}: {e}")
            return PolicyInjectionResult(
                resource_id=policy_name,
                policy_type=PolicyType.IAM.value,
                action="update",
                status="failed",
                error=str(e)
            )
    
    async def inject_s3_bucket_policy(self, bucket_name: str, policy_document: Dict[str, Any]) -> PolicyInjectionResult:
        """Inject S3 bucket policy."""
        try:
            # Merge with existing policy if present
            try:
                existing_policy = self.s3_client.get_bucket_policy(Bucket=bucket_name)
                existing_statements = json.loads(existing_policy['Policy'])['Statement']
                policy_document['Statement'].extend(existing_statements)
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                    raise
            
            # Apply policy
            self.s3_client.put_bucket_policy(
                Bucket=bucket_name,
                Policy=json.dumps(policy_document)
            )
            
            logger.info(f"Injected S3 bucket policy for {bucket_name}")
            
            return PolicyInjectionResult(
                resource_id=bucket_name,
                policy_type=PolicyType.S3_BUCKET.value,
                action="inject",
                status="success"
            )
            
        except Exception as e:
            logger.error(f"Failed to inject S3 bucket policy for {bucket_name}: {e}")
            return PolicyInjectionResult(
                resource_id=bucket_name,
                policy_type=PolicyType.S3_BUCKET.value,
                action="inject",
                status="failed",
                error=str(e)
            )
    
    async def inject_kms_key_policy(self, key_id: str, policy_document: Dict[str, Any]) -> PolicyInjectionResult:
        """Inject KMS key policy."""
        try:
            self.kms_client.put_key_policy(
                KeyId=key_id,
                PolicyName='default',
                Policy=json.dumps(policy_document)
            )
            
            logger.info(f"Injected KMS key policy for {key_id}")
            
            return PolicyInjectionResult(
                resource_id=key_id,
                policy_type=PolicyType.KMS.value,
                action="inject",
                status="success"
            )
            
        except Exception as e:
            logger.error(f"Failed to inject KMS key policy for {key_id}: {e}")
            return PolicyInjectionResult(
                resource_id=key_id,
                policy_type=PolicyType.KMS.value,
                action="inject",
                status="failed",
                error=str(e)
            )
    
    async def inject_compliance_policies(self, framework: str, resources: Dict[str, List[str]]) -> Dict[str, Any]:
        """
        Inject compliance policies for specific framework.
        
        Args:
            framework: Compliance framework (gdpr, pci, hipaa)
            resources: Dict of resource_type -> resource_ids
        
        Returns:
            Summary of policy injection results
        """
        results = []
        
        try:
            if framework.lower() == 'gdpr':
                policy_doc = self.gdpr_data_access_policy
            elif framework.lower() == 'pci':
                policy_doc = self.pci_encryption_policy
            elif framework.lower() == 'hipaa':
                policy_doc = self.hipaa_access_control_policy
            else:
                raise ValueError(f"Unknown framework: {framework}")
            
            # Inject IAM policy
            policy_name = f"{framework.upper()}CompliancePolicy"
            result = await self.inject_iam_policy(policy_name, policy_doc)
            results.append(result)
            
            # Inject S3 bucket policies
            if 's3_buckets' in resources:
                for bucket_name in resources['s3_buckets']:
                    result = await self.inject_s3_bucket_policy(bucket_name, policy_doc)
                    results.append(result)
            
            # Inject KMS key policies
            if 'kms_keys' in resources:
                for key_id in resources['kms_keys']:
                    result = await self.inject_kms_key_policy(key_id, policy_doc)
                    results.append(result)
            
            summary = {
                "framework": framework,
                "total_injections": len(results),
                "successful": len([r for r in results if r.status == "success"]),
                "failed": len([r for r in results if r.status == "failed"]),
                "results": [self._result_to_dict(r) for r in results]
            }
            
            logger.info(f"Injected {summary['successful']}/{summary['total_injections']} policies for {framework}")
            
            return summary
            
        except Exception as e:
            logger.error(f"Failed to inject compliance policies: {e}")
            raise
    
    async def attach_policy_to_role(self, policy_arn: str, role_name: str) -> bool:
        """Attach policy to IAM role."""
        try:
            self.iam_client.attach_role_policy(
                RoleName=role_name,
                PolicyArn=policy_arn
            )
            
            logger.info(f"Attached policy {policy_arn} to role {role_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to attach policy to role: {e}")
            return False
    
    async def attach_policy_to_user(self, policy_arn: str, user_name: str) -> bool:
        """Attach policy to IAM user."""
        try:
            self.iam_client.attach_user_policy(
                UserName=user_name,
                PolicyArn=policy_arn
            )
            
            logger.info(f"Attached policy {policy_arn} to user {user_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to attach policy to user: {e}")
            return False
    
    async def attach_policy_to_group(self, policy_arn: str, group_name: str) -> bool:
        """Attach policy to IAM group."""
        try:
            self.iam_client.attach_group_policy(
                GroupName=group_name,
                PolicyArn=policy_arn
            )
            
            logger.info(f"Attached policy {policy_arn} to group {group_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to attach policy to group: {e}")
            return False
    
    async def validate_policy(self, policy_document: Dict[str, Any]) -> Dict[str, Any]:
        """Validate IAM policy document."""
        try:
            # Use IAM policy simulator
            response = self.iam_client.simulate_custom_policy(
                PolicyInputList=[json.dumps(policy_document)],
                ActionNames=['s3:GetObject'],  # Example action
                ResourceArns=['arn:aws:s3:::example-bucket/*']
            )
            
            return {
                "valid": True,
                "evaluation_results": response.get('EvaluationResults', [])
            }
            
        except Exception as e:
            logger.error(f"Policy validation failed: {e}")
            return {
                "valid": False,
                "error": str(e)
            }
    
    def _result_to_dict(self, result: PolicyInjectionResult) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "resource_id": result.resource_id,
            "policy_type": result.policy_type,
            "action": result.action,
            "status": result.status,
            "policy_arn": result.policy_arn,
            "error": result.error
        }
