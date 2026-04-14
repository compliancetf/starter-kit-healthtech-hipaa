################################################################################
# Network
################################################################################

output "vpc_id" {
  description = "ID of the VPC"
  value       = module.vpc.vpc_id
}

output "private_subnet_ids" {
  description = "IDs of private subnets"
  value       = module.vpc.private_subnets
}

output "public_subnet_ids" {
  description = "IDs of public subnets"
  value       = module.vpc.public_subnets
}

################################################################################
# Load Balancer
################################################################################

output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = module.alb.dns_name
}

output "api_gateway_endpoint" {
  description = "API Gateway V2 endpoint URL"
  value       = module.apigateway.api_endpoint
}

################################################################################
# EKS
################################################################################

output "eks_cluster_name" {
  description = "Name of the EKS cluster"
  value       = module.eks.cluster_name
}

output "eks_cluster_endpoint" {
  description = "Endpoint for the EKS cluster API server"
  value       = module.eks.cluster_endpoint
}

output "eks_cluster_certificate_authority_data" {
  description = "Base64-encoded certificate data for the EKS cluster"
  value       = module.eks.cluster_certificate_authority_data
  sensitive   = true
}

################################################################################
# Databases
################################################################################

output "rds_endpoint" {
  description = "Endpoint for the standard RDS PostgreSQL instance"
  value       = module.rds.db_instance_endpoint
}

output "aurora_cluster_endpoint" {
  description = "Writer endpoint for the Aurora cluster"
  value       = module.rds_aurora.cluster_endpoint
}

output "aurora_cluster_reader_endpoint" {
  description = "Reader endpoint for the Aurora cluster"
  value       = module.rds_aurora.cluster_reader_endpoint
}

################################################################################
# Storage
################################################################################

output "s3_bucket_phi_id" {
  description = "Name of the PHI S3 bucket (object lock enabled)"
  value       = module.s3_bucket_phi.s3_bucket_id
}

output "s3_bucket_logs_id" {
  description = "Name of the S3 logs bucket"
  value       = module.s3_bucket_logs.s3_bucket_id
}

output "efs_id" {
  description = "ID of the EFS file system"
  value       = module.efs.id
}

################################################################################
# DynamoDB
################################################################################

output "dynamodb_table_name" {
  description = "Name of the DynamoDB table"
  value       = module.dynamodb.dynamodb_table_id
}

################################################################################
# Cache
################################################################################

output "elasticache_primary_endpoint" {
  description = "Primary endpoint of the ElastiCache replication group"
  value       = module.elasticache.replication_group_primary_endpoint_address
}

################################################################################
# Messaging
################################################################################

output "sqs_queue_url" {
  description = "URL of the SQS queue"
  value       = module.sqs.queue_url
}

output "sqs_dead_letter_queue_url" {
  description = "URL of the SQS dead-letter queue"
  value       = module.sqs.dead_letter_queue_url
}

################################################################################
# Search
################################################################################

output "opensearch_endpoint" {
  description = "Domain-specific endpoint for OpenSearch"
  value       = module.opensearch.domain_endpoint
}

################################################################################
# WAF
################################################################################

output "waf_web_acl_arn" {
  description = "ARN of the WAF WebACL"
  value       = module.waf.web_acl_arn
}
