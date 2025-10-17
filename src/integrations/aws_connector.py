"""AWS services integration for compliance scanning."""

from typing import Dict, Any, List, Optional
import boto3
from botocore.exceptions import ClientError

from ..utils.logger import get_logger

logger = get_logger(__name__)


class AWSConnector:
    """
    AWS services integration for comprehensive compliance scanning.
    
    Scans:
    - S3 buckets
    - EC2 instances
    - RDS databases
    - DynamoDB tables
    - Lambda functions
    - IAM policies
    - CloudTrail logs
    - Security groups
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize AWS connector."""
        self.config = config or {}
        
        # Initialize AWS clients
        self.s3 = boto3.client('s3')
        self.ec2 = boto3.client('ec2')
        self.rds = boto3.client('rds')
        self.dynamodb = boto3.client('dynamodb')
        self.lambda_client = boto3.client('lambda')
        self.iam = boto3.client('iam')
        self.cloudtrail = boto3.client('cloudtrail')
        self.sts = boto3.client('sts')
    
    async def scan_s3_buckets(self) -> Dict[str, Any]:
        """Scan all S3 buckets for compliance."""
        try:
            logger.info("Scanning S3 buckets")
            
            response = self.s3.list_buckets()
            buckets = response.get('Buckets', [])
            
            bucket_details = []
            for bucket in buckets:
                bucket_name = bucket['Name']
                details = await self._scan_s3_bucket(bucket_name)
                bucket_details.append(details)
            
            return {
                "total_buckets": len(buckets),
                "buckets": bucket_details
            }
        
        except Exception as e:
            logger.error(f"Failed to scan S3 buckets: {e}")
            raise
    
    async def _scan_s3_bucket(self, bucket_name: str) -> Dict[str, Any]:
        """Scan individual S3 bucket."""
        details = {
            "name": bucket_name,
            "encryption": False,
            "versioning": False,
            "logging": False,
            "public_access": False,
            "mfa_delete": False
        }
        
        try:
            # Check encryption
            try:
                encryption = self.s3.get_bucket_encryption(Bucket=bucket_name)
                details["encryption"] = True
                details["encryption_type"] = encryption['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']
            except ClientError:
                pass
            
            # Check versioning
            try:
                versioning = self.s3.get_bucket_versioning(Bucket=bucket_name)
                details["versioning"] = versioning.get('Status') == 'Enabled'
                details["mfa_delete"] = versioning.get('MFADelete') == 'Enabled'
            except ClientError:
                pass
            
            # Check logging
            try:
                logging = self.s3.get_bucket_logging(Bucket=bucket_name)
                details["logging"] = 'LoggingEnabled' in logging
            except ClientError:
                pass
            
            # Check public access block
            try:
                public_access = self.s3.get_public_access_block(Bucket=bucket_name)
                config = public_access['PublicAccessBlockConfiguration']
                details["public_access"] = not all([
                    config.get('BlockPublicAcls', False),
                    config.get('BlockPublicPolicy', False),
                    config.get('IgnorePublicAcls', False),
                    config.get('RestrictPublicBuckets', False)
                ])
            except ClientError:
                details["public_access"] = True  # Assume public if not configured
        
        except Exception as e:
            logger.warning(f"Failed to scan bucket {bucket_name}: {e}")
        
        return details
    
    async def scan_ec2_instances(self) -> Dict[str, Any]:
        """Scan EC2 instances for compliance."""
        try:
            logger.info("Scanning EC2 instances")
            
            response = self.ec2.describe_instances()
            instances = []
            
            for reservation in response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_details = {
                        "instance_id": instance['InstanceId'],
                        "instance_type": instance['InstanceType'],
                        "state": instance['State']['Name'],
                        "encrypted_volumes": [],
                        "unencrypted_volumes": [],
                        "public_ip": instance.get('PublicIpAddress'),
                        "security_groups": [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]
                    }
                    
                    # Check volumes encryption
                    for bdm in instance.get('BlockDeviceMappings', []):
                        if 'Ebs' in bdm:
                            volume_id = bdm['Ebs']['VolumeId']
                            volume = self.ec2.describe_volumes(VolumeIds=[volume_id])
                            encrypted = volume['Volumes'][0]['Encrypted']
                            
                            if encrypted:
                                instance_details["encrypted_volumes"].append(volume_id)
                            else:
                                instance_details["unencrypted_volumes"].append(volume_id)
                    
                    instances.append(instance_details)
            
            return {
                "total_instances": len(instances),
                "instances": instances
            }
        
        except Exception as e:
            logger.error(f"Failed to scan EC2 instances: {e}")
            raise
    
    async def scan_rds_databases(self) -> Dict[str, Any]:
        """Scan RDS databases for compliance."""
        try:
            logger.info("Scanning RDS databases")
            
            response = self.rds.describe_db_instances()
            databases = []
            
            for db in response.get('DBInstances', []):
                db_details = {
                    "identifier": db['DBInstanceIdentifier'],
                    "engine": db['Engine'],
                    "engine_version": db['EngineVersion'],
                    "encrypted": db.get('StorageEncrypted', False),
                    "multi_az": db.get('MultiAZ', False),
                    "publicly_accessible": db.get('PubliclyAccessible', False),
                    "backup_retention": db.get('BackupRetentionPeriod', 0),
                    "auto_minor_version_upgrade": db.get('AutoMinorVersionUpgrade', False)
                }
                
                databases.append(db_details)
            
            return {
                "total_databases": len(databases),
                "databases": databases
            }
        
        except Exception as e:
            logger.error(f"Failed to scan RDS databases: {e}")
            raise
    
    async def scan_dynamodb_tables(self) -> Dict[str, Any]:
        """Scan DynamoDB tables for compliance."""
        try:
            logger.info("Scanning DynamoDB tables")
            
            response = self.dynamodb.list_tables()
            table_names = response.get('TableNames', [])
            
            tables = []
            for table_name in table_names:
                table_details = self.dynamodb.describe_table(TableName=table_name)
                table = table_details['Table']
                
                sse_description = table.get('SSEDescription', {})
                
                table_info = {
                    "name": table_name,
                    "status": table['TableStatus'],
                    "item_count": table.get('ItemCount', 0),
                    "encrypted": sse_description.get('Status') == 'ENABLED',
                    "encryption_type": sse_description.get('SSEType'),
                    "point_in_time_recovery": False
                }
                
                # Check point-in-time recovery
                try:
                    pitr = self.dynamodb.describe_continuous_backups(TableName=table_name)
                    table_info["point_in_time_recovery"] = pitr['ContinuousBackupsDescription']['PointInTimeRecoveryDescription']['PointInTimeRecoveryStatus'] == 'ENABLED'
                except ClientError:
                    pass
                
                tables.append(table_info)
            
            return {
                "total_tables": len(tables),
                "tables": tables
            }
        
        except Exception as e:
            logger.error(f"Failed to scan DynamoDB tables: {e}")
            raise
    
    async def scan_lambda_functions(self) -> Dict[str, Any]:
        """Scan Lambda functions for compliance."""
        try:
            logger.info("Scanning Lambda functions")
            
            response = self.lambda_client.list_functions()
            functions = []
            
            for func in response.get('Functions', []):
                func_details = {
                    "name": func['FunctionName'],
                    "runtime": func['Runtime'],
                    "role": func['Role'],
                    "vpc_config": bool(func.get('VpcConfig', {}).get('VpcId')),
                    "environment_variables": bool(func.get('Environment', {}).get('Variables')),
                    "tracing": func.get('TracingConfig', {}).get('Mode', 'PassThrough')
                }
                
                functions.append(func_details)
            
            return {
                "total_functions": len(functions),
                "functions": functions
            }
        
        except Exception as e:
            logger.error(f"Failed to scan Lambda functions: {e}")
            raise
    
    async def scan_iam_policies(self) -> Dict[str, Any]:
        """Scan IAM policies for compliance."""
        try:
            logger.info("Scanning IAM policies")
            
            # Get account password policy
            try:
                password_policy = self.iam.get_account_password_policy()
                password_policy_details = password_policy['PasswordPolicy']
            except ClientError:
                password_policy_details = {}
            
            # List users
            users_response = self.iam.list_users()
            users = users_response.get('Users', [])
            
            # List roles
            roles_response = self.iam.list_roles()
            roles = roles_response.get('Roles', [])
            
            # Check for users with admin access
            admin_users = []
            for user in users:
                user_name = user['UserName']
                
                # Check attached policies
                attached_policies = self.iam.list_attached_user_policies(UserName=user_name)
                for policy in attached_policies.get('AttachedPolicies', []):
                    if 'Admin' in policy['PolicyName']:
                        admin_users.append(user_name)
                        break
            
            return {
                "password_policy": password_policy_details,
                "total_users": len(users),
                "total_roles": len(roles),
                "admin_users": admin_users
            }
        
        except Exception as e:
            logger.error(f"Failed to scan IAM policies: {e}")
            raise
    
    async def scan_cloudtrail(self) -> Dict[str, Any]:
        """Scan CloudTrail configuration."""
        try:
            logger.info("Scanning CloudTrail")
            
            response = self.cloudtrail.describe_trails()
            trails = []
            
            for trail in response.get('trailList', []):
                trail_status = self.cloudtrail.get_trail_status(Name=trail['TrailARN'])
                
                trail_details = {
                    "name": trail['Name'],
                    "is_logging": trail_status['IsLogging'],
                    "is_multi_region": trail.get('IsMultiRegionTrail', False),
                    "log_file_validation_enabled": trail.get('LogFileValidationEnabled', False),
                    "s3_bucket": trail.get('S3BucketName'),
                    "kms_key_id": trail.get('KmsKeyId')
                }
                
                trails.append(trail_details)
            
            return {
                "total_trails": len(trails),
                "trails": trails,
                "multi_region_enabled": any(t['is_multi_region'] for t in trails)
            }
        
        except Exception as e:
            logger.error(f"Failed to scan CloudTrail: {e}")
            raise
    
    async def comprehensive_scan(self) -> Dict[str, Any]:
        """Perform comprehensive AWS compliance scan."""
        try:
            logger.info("Starting comprehensive AWS scan")
            
            # Get account info
            account_info = self.sts.get_caller_identity()
            
            results = {
                "account_id": account_info['Account'],
                "s3": await self.scan_s3_buckets(),
                "ec2": await self.scan_ec2_instances(),
                "rds": await self.scan_rds_databases(),
                "dynamodb": await self.scan_dynamodb_tables(),
                "lambda": await self.scan_lambda_functions(),
                "iam": await self.scan_iam_policies(),
                "cloudtrail": await self.scan_cloudtrail()
            }
            
            logger.info("Comprehensive AWS scan completed")
            
            return results
        
        except Exception as e:
            logger.error(f"Comprehensive AWS scan failed: {e}")
            raise
