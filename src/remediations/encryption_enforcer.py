"""Encryption enforcement system."""

import os
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum

import boto3
from botocore.exceptions import ClientError

from ..utils.logger import get_logger
from ..utils.encryption import EncryptionManager

logger = get_logger(__name__)


class EncryptionStatus(Enum):
    """Encryption status."""
    ENCRYPTED = "encrypted"
    UNENCRYPTED = "unencrypted"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


@dataclass
class EncryptionResult:
    """Result of encryption enforcement."""
    
    resource_id: str
    resource_type: str
    action: str
    status: str
    encryption_type: Optional[str] = None
    kms_key_id: Optional[str] = None
    error: Optional[str] = None


class EncryptionEnforcer:
    """
    Automated encryption enforcement system.
    
    Enforces encryption for:
    - S3 buckets (at rest and in transit)
    - EBS volumes
    - RDS databases
    - DynamoDB tables
    - SNS topics
    - SQS queues
    - Secrets Manager secrets
    - Systems Manager parameters
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize encryption enforcer."""
        self.config = config or {}
        self.encryption_manager = EncryptionManager(config)
        
        # AWS clients
        self.s3_client = boto3.client('s3')
        self.ec2_client = boto3.client('ec2')
        self.rds_client = boto3.client('rds')
        self.dynamodb_client = boto3.client('dynamodb')
        self.kms_client = boto3.client('kms')
        
        # Default KMS key
        self.default_kms_key = config.get('default_kms_key_id')
    
    async def enforce_s3_encryption(self, bucket_name: str) -> EncryptionResult:
        """Enforce S3 bucket encryption."""
        try:
            # Check current encryption
            try:
                response = self.s3_client.get_bucket_encryption(Bucket=bucket_name)
                logger.info(f"S3 bucket {bucket_name} already encrypted")
                
                return EncryptionResult(
                    resource_id=bucket_name,
                    resource_type="s3_bucket",
                    action="verify",
                    status="encrypted",
                    encryption_type="AES256",
                    kms_key_id=self._extract_kms_key(response)
                )
                
            except ClientError as e:
                if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    # Enable encryption
                    encryption_config = {
                        'Rules': [{
                            'ApplyServerSideEncryptionByDefault': {
                                'SSEAlgorithm': 'aws:kms',
                                'KMSMasterKeyID': self.default_kms_key
                            },
                            'BucketKeyEnabled': True
                        }]
                    }
                    
                    self.s3_client.put_bucket_encryption(
                        Bucket=bucket_name,
                        ServerSideEncryptionConfiguration=encryption_config
                    )
                    
                    logger.info(f"Enabled encryption for S3 bucket {bucket_name}")
                    
                    return EncryptionResult(
                        resource_id=bucket_name,
                        resource_type="s3_bucket",
                        action="enable_encryption",
                        status="encrypted",
                        encryption_type="aws:kms",
                        kms_key_id=self.default_kms_key
                    )
                else:
                    raise
            
            # Enforce bucket policy for HTTPS
            await self._enforce_s3_https_policy(bucket_name)
            
        except Exception as e:
            logger.error(f"Failed to enforce S3 encryption for {bucket_name}: {e}")
            return EncryptionResult(
                resource_id=bucket_name,
                resource_type="s3_bucket",
                action="enable_encryption",
                status="failed",
                error=str(e)
            )
    
    async def _enforce_s3_https_policy(self, bucket_name: str) -> None:
        """Enforce HTTPS-only access for S3 bucket."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "EnforceHTTPS",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [
                    f"arn:aws:s3:::{bucket_name}",
                    f"arn:aws:s3:::{bucket_name}/*"
                ],
                "Condition": {
                    "Bool": {
                        "aws:SecureTransport": "false"
                    }
                }
            }]
        }
        
        try:
            import json
            self.s3_client.put_bucket_policy(
                Bucket=bucket_name,
                Policy=json.dumps(policy)
            )
            logger.info(f"Enforced HTTPS policy for S3 bucket {bucket_name}")
        except Exception as e:
            logger.warning(f"Failed to enforce HTTPS policy: {e}")
    
    async def enforce_ebs_encryption(self, volume_id: str) -> EncryptionResult:
        """Enforce EBS volume encryption."""
        try:
            # Check current encryption
            response = self.ec2_client.describe_volumes(VolumeIds=[volume_id])
            volume = response['Volumes'][0]
            
            if volume.get('Encrypted', False):
                logger.info(f"EBS volume {volume_id} already encrypted")
                
                return EncryptionResult(
                    resource_id=volume_id,
                    resource_type="ebs_volume",
                    action="verify",
                    status="encrypted",
                    kms_key_id=volume.get('KmsKeyId')
                )
            
            # Create encrypted snapshot
            snapshot_response = self.ec2_client.create_snapshot(
                VolumeId=volume_id,
                Description=f"Snapshot for encryption of {volume_id}"
            )
            snapshot_id = snapshot_response['SnapshotId']
            
            # Wait for snapshot to complete
            waiter = self.ec2_client.get_waiter('snapshot_completed')
            waiter.wait(SnapshotIds=[snapshot_id])
            
            # Create encrypted copy
            encrypted_snapshot = self.ec2_client.copy_snapshot(
                SourceSnapshotId=snapshot_id,
                SourceRegion=os.environ.get('AWS_REGION', 'us-east-1'),
                Description=f"Encrypted snapshot of {volume_id}",
                Encrypted=True,
                KmsKeyId=self.default_kms_key
            )
            
            logger.info(f"Created encrypted snapshot for EBS volume {volume_id}")
            
            return EncryptionResult(
                resource_id=volume_id,
                resource_type="ebs_volume",
                action="create_encrypted_snapshot",
                status="encrypted",
                kms_key_id=self.default_kms_key
            )
            
        except Exception as e:
            logger.error(f"Failed to enforce EBS encryption for {volume_id}: {e}")
            return EncryptionResult(
                resource_id=volume_id,
                resource_type="ebs_volume",
                action="enable_encryption",
                status="failed",
                error=str(e)
            )
    
    async def enforce_rds_encryption(self, db_instance_id: str) -> EncryptionResult:
        """Enforce RDS database encryption."""
        try:
            # Check current encryption
            response = self.rds_client.describe_db_instances(
                DBInstanceIdentifier=db_instance_id
            )
            db_instance = response['DBInstances'][0]
            
            if db_instance.get('StorageEncrypted', False):
                logger.info(f"RDS instance {db_instance_id} already encrypted")
                
                return EncryptionResult(
                    resource_id=db_instance_id,
                    resource_type="rds_instance",
                    action="verify",
                    status="encrypted",
                    kms_key_id=db_instance.get('KmsKeyId')
                )
            
            # Create encrypted snapshot
            snapshot_id = f"{db_instance_id}-encrypted-{os.urandom(4).hex()}"
            
            self.rds_client.create_db_snapshot(
                DBSnapshotIdentifier=snapshot_id,
                DBInstanceIdentifier=db_instance_id
            )
            
            # Wait for snapshot
            waiter = self.rds_client.get_waiter('db_snapshot_completed')
            waiter.wait(DBSnapshotIdentifier=snapshot_id)
            
            # Copy snapshot with encryption
            encrypted_snapshot_id = f"{snapshot_id}-encrypted"
            
            self.rds_client.copy_db_snapshot(
                SourceDBSnapshotIdentifier=snapshot_id,
                TargetDBSnapshotIdentifier=encrypted_snapshot_id,
                KmsKeyId=self.default_kms_key
            )
            
            logger.info(f"Created encrypted snapshot for RDS instance {db_instance_id}")
            
            return EncryptionResult(
                resource_id=db_instance_id,
                resource_type="rds_instance",
                action="create_encrypted_snapshot",
                status="encrypted",
                kms_key_id=self.default_kms_key
            )
            
        except Exception as e:
            logger.error(f"Failed to enforce RDS encryption for {db_instance_id}: {e}")
            return EncryptionResult(
                resource_id=db_instance_id,
                resource_type="rds_instance",
                action="enable_encryption",
                status="failed",
                error=str(e)
            )
    
    async def enforce_dynamodb_encryption(self, table_name: str) -> EncryptionResult:
        """Enforce DynamoDB table encryption."""
        try:
            # Check current encryption
            response = self.dynamodb_client.describe_table(TableName=table_name)
            table = response['Table']
            
            sse_description = table.get('SSEDescription', {})
            if sse_description.get('Status') == 'ENABLED':
                logger.info(f"DynamoDB table {table_name} already encrypted")
                
                return EncryptionResult(
                    resource_id=table_name,
                    resource_type="dynamodb_table",
                    action="verify",
                    status="encrypted",
                    encryption_type=sse_description.get('SSEType'),
                    kms_key_id=sse_description.get('KMSMasterKeyArn')
                )
            
            # Enable encryption
            self.dynamodb_client.update_table(
                TableName=table_name,
                SSESpecification={
                    'Enabled': True,
                    'SSEType': 'KMS',
                    'KMSMasterKeyId': self.default_kms_key
                }
            )
            
            logger.info(f"Enabled encryption for DynamoDB table {table_name}")
            
            return EncryptionResult(
                resource_id=table_name,
                resource_type="dynamodb_table",
                action="enable_encryption",
                status="encrypted",
                encryption_type="KMS",
                kms_key_id=self.default_kms_key
            )
            
        except Exception as e:
            logger.error(f"Failed to enforce DynamoDB encryption for {table_name}: {e}")
            return EncryptionResult(
                resource_id=table_name,
                resource_type="dynamodb_table",
                action="enable_encryption",
                status="failed",
                error=str(e)
            )
    
    async def scan_and_enforce(self, resource_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """Scan for unencrypted resources and enforce encryption."""
        resource_types = resource_types or ['s3', 'ebs', 'rds', 'dynamodb']
        results = []
        
        try:
            if 's3' in resource_types:
                # List all S3 buckets
                response = self.s3_client.list_buckets()
                for bucket in response['Buckets']:
                    result = await self.enforce_s3_encryption(bucket['Name'])
                    results.append(result)
            
            if 'ebs' in resource_types:
                # List unencrypted EBS volumes
                response = self.ec2_client.describe_volumes(
                    Filters=[{'Name': 'encrypted', 'Values': ['false']}]
                )
                for volume in response['Volumes']:
                    result = await self.enforce_ebs_encryption(volume['VolumeId'])
                    results.append(result)
            
            if 'rds' in resource_types:
                # List RDS instances
                response = self.rds_client.describe_db_instances()
                for db_instance in response['DBInstances']:
                    result = await self.enforce_rds_encryption(
                        db_instance['DBInstanceIdentifier']
                    )
                    results.append(result)
            
            if 'dynamodb' in resource_types:
                # List DynamoDB tables
                response = self.dynamodb_client.list_tables()
                for table_name in response['TableNames']:
                    result = await self.enforce_dynamodb_encryption(table_name)
                    results.append(result)
            
            summary = {
                "total_resources": len(results),
                "encrypted": len([r for r in results if r.status == "encrypted"]),
                "failed": len([r for r in results if r.status == "failed"]),
                "results": [self._result_to_dict(r) for r in results]
            }
            
            logger.info(f"Encryption enforcement completed: {summary['encrypted']}/{summary['total_resources']} encrypted")
            
            return summary
            
        except Exception as e:
            logger.error(f"Encryption enforcement scan failed: {e}")
            raise
    
    def _extract_kms_key(self, encryption_response: Dict[str, Any]) -> Optional[str]:
        """Extract KMS key ID from encryption response."""
        try:
            rules = encryption_response.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
            if rules:
                return rules[0].get('ApplyServerSideEncryptionByDefault', {}).get('KMSMasterKeyID')
        except Exception:
            pass
        return None
    
    def _result_to_dict(self, result: EncryptionResult) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "resource_id": result.resource_id,
            "resource_type": result.resource_type,
            "action": result.action,
            "status": result.status,
            "encryption_type": result.encryption_type,
            "kms_key_id": result.kms_key_id,
            "error": result.error
        }
