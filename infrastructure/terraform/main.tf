terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  
  backend "s3" {
    bucket         = "your-terraform-state-bucket"
    key            = "compliance-guardian/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
  }
}

provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "ComplianceGuardianAI"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# Variables
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "bedrock_model_id" {
  description = "Bedrock model ID"
  type        = string
  default     = "anthropic.claude-3-5-sonnet-20241022-v2:0"
}

# DynamoDB Table
resource "aws_dynamodb_table" "agent_memory" {
  name           = "${var.environment}-compliance-guardian-memory"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "agent_id"
  range_key      = "timestamp"
  
  attribute {
    name = "agent_id"
    type = "S"
  }
  
  attribute {
    name = "timestamp"
    type = "N"
  }
  
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"
  
  point_in_time_recovery {
    enabled = true
  }
  
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.encryption.arn
  }
  
  tags = {
    Name = "${var.environment}-agent-memory"
  }
}

# KMS Key
resource "aws_kms_key" "encryption" {
  description             = "KMS key for Compliance Guardian AI"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow services"
        Effect = "Allow"
        Principal = {
          Service = [
            "lambda.amazonaws.com",
            "dynamodb.amazonaws.com",
            "s3.amazonaws.com"
          ]
        }
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "encryption" {
  name          = "alias/${var.environment}-compliance-guardian"
  target_key_id = aws_kms_key.encryption.key_id
}

# S3 Bucket for Reports
resource "aws_s3_bucket" "reports" {
  bucket = "${var.environment}-compliance-guardian-reports-${data.aws_caller_identity.current.account_id}"
  
  tags = {
    Name = "${var.environment}-compliance-reports"
  }
}

resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.encryption.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket = aws_s3_bucket.reports.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id
  
  rule {
    id     = "delete-old-reports"
    status = "Enabled"
    
    expiration {
      days = 2555
    }
  }
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "application" {
  name              = "/aws/compliance-guardian/${var.environment}"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.encryption.arn
}

# IAM Role for Lambda
resource "aws_iam_role" "lambda_execution" {
  name = "${var.environment}-compliance-guardian-lambda-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "${var.environment}-compliance-guardian-policy"
  role = aws_iam_role.lambda_execution.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeAgent",
          "bedrock:InvokeModelWithResponseStream"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = aws_dynamodb_table.agent_memory.arn
      },
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.reports.arn,
          "${aws_s3_bucket.reports.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.encryption.arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.application.arn}:*"
      }
    ]
  })
}

# Lambda Function
resource "aws_lambda_function" "compliance_scan" {
  function_name = "${var.environment}-compliance-guardian-scan"
  role          = aws_iam_role.lambda_execution.arn
  runtime       = "python3.11"
  handler       = "index.handler"
  timeout       = 900
  memory_size   = 2048
  
  filename         = "lambda_placeholder.zip"
  source_code_hash = filebase64sha256("lambda_placeholder.zip")
  
  environment {
    variables = {
      DYNAMODB_TABLE   = aws_dynamodb_table.agent_memory.name
      REPORTS_BUCKET   = aws_s3_bucket.reports.id
      KMS_KEY_ID       = aws_kms_key.encryption.arn
      BEDROCK_MODEL_ID = var.bedrock_model_id
      ENVIRONMENT      = var.environment
    }
  }
}

# EventBridge Rule for Scheduled Scans
resource "aws_cloudwatch_event_rule" "scheduled_scan" {
  name                = "${var.environment}-compliance-scheduled-scan"
  description         = "Trigger daily compliance scan"
  schedule_expression = "rate(1 day)"
}

resource "aws_cloudwatch_event_target" "scan_lambda" {
  rule      = aws_cloudwatch_event_rule.scheduled_scan.name
  target_id = "ComplianceScanTarget"
  arn       = aws_lambda_function.compliance_scan.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.compliance_scan.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.scheduled_scan.arn
}

# SNS Topic for Alerts
resource "aws_sns_topic" "alerts" {
  name              = "${var.environment}-compliance-guardian-alerts"
  display_name      = "Compliance Guardian Alerts"
  kms_master_key_id = aws_kms_key.encryption.id
}

# CloudWatch Alarm
resource "aws_cloudwatch_metric_alarm" "critical_violations" {
  alarm_name          = "${var.environment}-compliance-critical-violations"
  alarm_description   = "Alert on critical compliance violations"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "CriticalViolations"
  namespace           = "ComplianceGuardianAI"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Data sources
data "aws_caller_identity" "current" {}

# Outputs
output "dynamodb_table_name" {
  description = "DynamoDB table name"
  value       = aws_dynamodb_table.agent_memory.name
}

output "reports_bucket_name" {
  description = "S3 bucket for reports"
  value       = aws_s3_bucket.reports.id
}

output "kms_key_id" {
  description = "KMS key ARN"
  value       = aws_kms_key.encryption.arn
}

output "lambda_role_arn" {
  description = "Lambda execution role ARN"
  value       = aws_iam_role.lambda_execution.arn
}

output "sns_topic_arn" {
  description = "SNS topic ARN"
  value       = aws_sns_topic.alerts.arn
}
