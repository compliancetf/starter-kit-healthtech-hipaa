################################################################################
# HIPAA Compliance Starter Kit - HealthTech
#
# Pre-composed infrastructure for healthtech companies (telehealth, EHR
# integration, clinical decision support) handling Protected Health Information.
# All modules source from the compliance.tf registry and enforce HIPAA Security
# Rule controls at terraform plan time.
#
# HIPAA Security Rule requirements enforced automatically:
#   164.312(a)(1)     - Access control (IAM auth, no public PHI access)
#   164.312(a)(2)(iv) - Encryption/decryption (KMS CMK at rest)
#   164.312(c)(1)     - Integrity (versioning, PITR, object lock)
#   164.312(d)        - Authentication (IAM auth, Redis Auth)
#   164.312(e)(1)     - Transmission security (TLS 1.2+ enforced)
#   164.312(e)(2)(ii) - Encryption in transit (HTTPS/TLS required)
#   164.310(d)(2)(iv) - Data backup (automated backups, cross-region replication)
#   164.312(b)        - Audit controls (CloudWatch, CloudTrail, access logging)
################################################################################

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terraform"
      Compliance  = "hipaa"
    }
  }
}

locals {
  name = "${var.project_name}-${var.environment}"
}

################################################################################
# Network
################################################################################

module "vpc" {
  source  = "hipaa.compliance.tf/terraform-aws-modules/vpc/aws"
  version = "~> 6.0"

  name = local.name
  cidr = var.vpc_cidr

  azs              = var.availability_zones
  public_subnets   = var.public_subnet_cidrs
  private_subnets  = var.private_subnet_cidrs
  database_subnets = var.database_subnet_cidrs

  create_database_subnet_group = true

  enable_nat_gateway = true
  single_nat_gateway = var.environment != "prod"

  # HIPAA 164.312(b): flow logs for PHI network audit trail
  enable_flow_log                      = true
  create_flow_log_cloudwatch_log_group = true

  tags = var.tags
}

################################################################################
# Load Balancer
################################################################################

module "alb" {
  source  = "hipaa.compliance.tf/terraform-aws-modules/alb/aws"
  version = "~> 10.0"

  name = local.name

  vpc_id  = module.vpc.vpc_id
  subnets = module.vpc.public_subnets

  enable_deletion_protection = var.environment == "prod"

  security_group_ingress_rules = {
    all_https = {
      from_port   = 443
      to_port     = 443
      ip_protocol = "tcp"
      cidr_ipv4   = "0.0.0.0/0"
      description = "HTTPS ingress"
    }
  }

  security_group_egress_rules = {
    all = {
      ip_protocol = "-1"
      cidr_ipv4   = module.vpc.vpc_cidr_block
      description = "All traffic to VPC"
    }
  }

  listeners = {
    https = {
      port            = 443
      protocol        = "HTTPS"
      certificate_arn = module.acm.acm_certificate_arn
      # HIPAA 164.312(e)(2)(ii): TLS 1.2 minimum
      ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"

      fixed_response = {
        content_type = "text/plain"
        message_body = "OK"
        status_code  = "200"
      }
    }
  }

  access_logs = {
    bucket = module.s3_bucket_logs.s3_bucket_id
    prefix = "alb"
  }

  tags = var.tags
}

################################################################################
# API Gateway V2 (HIPAA 164.312(b) - PHI route access logging)
################################################################################

module "apigateway" {
  source  = "hipaa.compliance.tf/terraform-aws-modules/apigateway-v2/aws"
  version = "~> 6.0"

  name          = "${local.name}-api"
  description   = "API Gateway - authorized PHI routes with access logging"
  protocol_type = "HTTP"

  # HIPAA 164.312(b): log all API calls for PHI access audit
  stage_access_log_settings = {
    destination_arn = module.cloudwatch.cloudwatch_log_group_arn
  }

  create_domain_name = false

  vpc_links = {
    alb_link = {
      name               = "${local.name}-vpc-link"
      subnet_ids         = module.vpc.private_subnets
      security_group_ids = [module.vpc.default_security_group_id]
    }
  }

  tags = var.tags
}

################################################################################
# WAF - Regional
################################################################################

module "waf" {
  source  = "hipaa.compliance.tf/terraform-aws-modules/wafv2/aws"
  version = "~> 1.0"

  name  = "${local.name}-waf"
  scope = "REGIONAL"

  default_action = "allow"

  rules = {
    common = {
      priority = 1
      statement = {
        managed_rule_group_statement = {
          name        = "AWSManagedRulesCommonRuleSet"
          vendor_name = "AWS"
        }
      }
      override_action = "none"
      visibility_config = {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name}-common-rules"
        sampled_requests_enabled   = true
      }
    }
    bad_inputs = {
      priority = 2
      statement = {
        managed_rule_group_statement = {
          name        = "AWSManagedRulesKnownBadInputsRuleSet"
          vendor_name = "AWS"
        }
      }
      override_action = "none"
      visibility_config = {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name}-bad-inputs"
        sampled_requests_enabled   = true
      }
    }
    ip_reputation = {
      priority = 3
      statement = {
        managed_rule_group_statement = {
          name        = "AWSManagedRulesAmazonIpReputationList"
          vendor_name = "AWS"
        }
      }
      override_action = "none"
      visibility_config = {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name}-ip-reputation"
        sampled_requests_enabled   = true
      }
    }
  }

  tags = var.tags
}

resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = module.alb.arn
  web_acl_arn  = module.waf.web_acl_arn
}

################################################################################
# Certificate (HIPAA 164.312(e)(2)(ii))
################################################################################

module "acm" {
  source  = "hipaa.compliance.tf/terraform-aws-modules/acm/aws"
  version = "~> 6.0"

  domain_name = var.domain_name
  zone_id     = var.route53_zone_id

  validation_method = "DNS"

  subject_alternative_names = [
    "*.${var.domain_name}",
    "api.${var.domain_name}",
  ]

  wait_for_validation = true

  tags = var.tags
}

################################################################################
# KMS - CMK for PHI encryption (HIPAA 164.312(a)(2)(iv))
################################################################################

module "kms" {
  source  = "hipaa.compliance.tf/terraform-aws-modules/kms/aws"
  version = "~> 4.0"

  description = "KMS CMK for ${local.name} PHI encryption (HIPAA 164.312(a)(2)(iv))"
  key_usage   = "ENCRYPT_DECRYPT"

  key_administrators = [data.aws_caller_identity.current.arn]
  key_users          = [data.aws_caller_identity.current.arn]

  key_service_roles_for_autoscaling = [
    "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
  ]

  key_statements = [
    {
      sid    = "AllowCloudWatchLogs"
      effect = "Allow"
      principals = [
        {
          type        = "Service"
          identifiers = ["logs.${var.aws_region}.amazonaws.com"]
        }
      ]
      actions = [
        "kms:Encrypt*",
        "kms:Decrypt*",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:Describe*",
      ]
      resources = ["*"]
      conditions = [
        {
          test     = "ArnLike"
          variable = "kms:EncryptionContext:aws:logs:arn"
          values   = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*"]
        }
      ]
    }
  ]

  aliases = ["${local.name}/phi"]

  tags = var.tags
}

################################################################################
# Compute - Lambda (VPC-attached, PHI processing)
################################################################################

module "lambda" {
  source  = "hipaa.compliance.tf/terraform-aws-modules/lambda/aws"
  version = "~> 8.0"

  function_name = "${local.name}-function"
  description   = "PHI processing function - VPC-attached, KMS encrypted"
  runtime       = var.lambda_runtime
  handler       = "index.handler"

  # HIPAA 164.312(a)(1): Lambda in VPC for PHI network isolation
  vpc_subnet_ids         = module.vpc.private_subnets
  vpc_security_group_ids = [module.vpc.default_security_group_id]

  # HIPAA 164.312(a)(2)(iv): KMS encryption for environment variables
  kms_key_arn = module.kms.key_arn

  # HIPAA 164.312(b): encrypt CloudWatch Logs with KMS
  cloudwatch_logs_kms_key_id = module.kms.key_arn

  # HIPAA: limit concurrent executions to prevent runaway PHI processing
  reserved_concurrent_executions = 10

  dead_letter_target_arn = module.sqs.dead_letter_queue_arn

  create_package = false
  s3_existing_package = {
    bucket = module.s3_bucket_phi.s3_bucket_id
    key    = "lambda/function.zip"
  }

  tags = var.tags
}

################################################################################
# Compute - EC2 (private, IMDSv2, PHI processing zone)
################################################################################

module "ec2_instance" {
  source  = "hipaa.compliance.tf/terraform-aws-modules/ec2-instance/aws"
  version = "~> 6.0"

  name = "${local.name}-worker"

  instance_type               = var.ec2_instance_type
  ami                         = data.aws_ami.amazon_linux_2.id
  subnet_id                   = module.vpc.private_subnets[0]
  associate_public_ip_address = false

  # HIPAA 164.312(a)(1): IMDSv2 prevents credential exposure
  metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  create_iam_instance_profile = true
  iam_instance_profile        = "${local.name}-worker"
  iam_role_policies = {
    ssm = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  }

  monitoring = true

  tags = var.tags
}

data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

################################################################################
# Compute - EKS (PHI processing zone)
################################################################################

module "eks" {
  source  = "hipaa.compliance.tf/terraform-aws-modules/eks/aws"
  version = "= 21.17.1"

  name               = local.name
  kubernetes_version = var.eks_cluster_version

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  endpoint_public_access  = true
  endpoint_private_access = true

  cloudwatch_log_group_kms_key_id = module.kms.key_arn

  # HIPAA: encrypt Kubernetes secrets with CMK
  encryption_config = {
    provider_key_arn = module.kms.key_arn
  }

  addons = {
    coredns                = {}
    eks-pod-identity-agent = {}
    kube-proxy             = {}
    vpc-cni                = {}
  }

  eks_managed_node_groups = {
    default = {
      instance_types = var.eks_node_instance_types
      min_size       = var.eks_node_min_size
      max_size       = var.eks_node_max_size
      desired_size   = var.eks_node_desired_size
    }
  }

  tags = var.tags
}

################################################################################
# Database - RDS PostgreSQL
# CRITICAL: storage_encrypted must be true at creation - cannot be retrofitted
################################################################################

module "rds" {
  source  = "hipaa.compliance.tf/terraform-aws-modules/rds/aws"
  version = "~> 7.0"

  identifier           = "${local.name}-rds"
  engine               = "postgres"
  engine_version       = var.rds_engine_version
  family               = "postgres16"
  major_engine_version = "16"
  instance_class       = var.rds_instance_class

  allocated_storage     = 20
  max_allocated_storage = 100

  db_name  = "app_db"
  username = "app_admin"

  db_subnet_group_name   = module.vpc.database_subnet_group_name
  vpc_security_group_ids = [module.vpc.default_security_group_id]

  # HIPAA CRITICAL: encryption must be enabled at creation, cannot be added later
  storage_encrypted = true
  kms_key_id        = module.kms.key_arn

  # HIPAA 164.310(d)(2)(iv): automated backups, 7-day minimum
  backup_retention_period = var.environment == "prod" ? 14 : 7
  backup_window           = "03:00-06:00"
  maintenance_window      = "mon:05:00-mon:06:00"

  deletion_protection = var.environment == "prod"

  # HIPAA 164.312(b): enhanced monitoring and log exports
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  monitoring_interval             = 60
  create_monitoring_role          = true

  iam_database_authentication_enabled = true

  tags = var.tags
}

################################################################################
# Database - Aurora PostgreSQL (with backtracking for PHI integrity)
################################################################################

module "rds_aurora" {
  source  = "hipaa.compliance.tf/terraform-aws-modules/rds-aurora/aws"
  version = "~> 10.0"

  name            = "${local.name}-aurora"
  engine          = "aurora-postgresql"
  engine_version  = var.aurora_engine_version
  master_username = var.aurora_master_username

  instances = {
    writer = { instance_class = var.aurora_instance_class }
    reader = { instance_class = var.aurora_instance_class }
  }

  vpc_id               = module.vpc.vpc_id
  db_subnet_group_name = module.vpc.database_subnet_group_name
  subnets              = module.vpc.private_subnets

  security_group_ingress_rules = {
    vpc_ingress = { cidr_ipv4 = module.vpc.vpc_cidr_block }
  }

  storage_encrypted       = true
  apply_immediately       = var.environment != "prod"
  backup_retention_period = var.environment == "prod" ? 14 : 7
  deletion_protection     = var.environment == "prod"

  enabled_cloudwatch_logs_exports     = ["postgresql"]
  iam_database_authentication_enabled = true

  tags = var.tags
}

################################################################################
# DynamoDB (HIPAA 164.312(a)(2)(iv) + 164.312(c)(1))
################################################################################

module "dynamodb" {
  source  = "hipaa.compliance.tf/terraform-aws-modules/dynamodb-table/aws"
  version = "~> 5.0"

  name     = "${local.name}-table"
  hash_key = "pk"

  attributes = [{ name = "pk", type = "S" }]

  billing_mode                   = "PAY_PER_REQUEST"
  deletion_protection_enabled    = var.environment == "prod"
  point_in_time_recovery_enabled = true
  server_side_encryption_enabled = true

  tags = var.tags
}

################################################################################
# Storage - S3 PHI (object lock for integrity, HIPAA 164.312(c)(1); retention floor from 164.316(b)(2)(i), see variables.tf)
################################################################################

module "s3_bucket_phi" {
  source  = "hipaa.compliance.tf/terraform-aws-modules/s3-bucket/aws"
  version = "~> 5.0"

  bucket = "${local.name}-phi-${data.aws_caller_identity.current.account_id}"

  versioning = { enabled = "Enabled" }

  # HIPAA 164.312(c)(1): object lock prevents deletion or modification of PHI records
  object_lock_enabled = true
  object_lock_configuration = {
    object_lock_enabled = "Enabled"
    rule = {
      default_retention = {
        mode  = "GOVERNANCE"
        # 6-year floor tracks the HIPAA documentation retention minimum (164.316(b)(2)(i)); clinical retention is state law - set via phi_retention_years
        years = var.phi_retention_years
      }
    }
  }

  logging = {
    target_bucket = module.s3_bucket_logs.s3_bucket_id
    target_prefix = "s3/phi/"
  }

  # HIPAA 164.310(d)(2)(iv): cross-region replication for PHI durability
  replication_configuration = {
    role = var.s3_replication_role_arn
    rules = [
      {
        id     = "replicate-phi"
        status = "Enabled"
        destination = {
          bucket        = var.s3_replication_destination_bucket_arn
          storage_class = "STANDARD"
        }
      }
    ]
  }

  lifecycle_rule = [
    {
      id     = "phi-tiering"
      status = "Enabled"
      transition = [
        { days = 365, storage_class = "STANDARD_IA" },
        { days = 730, storage_class = "GLACIER" }
      ]
    }
  ]

  tags = var.tags
}

################################################################################
# Storage - S3 logs
################################################################################

module "s3_bucket_logs" {
  source  = "hipaa.compliance.tf/terraform-aws-modules/s3-bucket/aws"
  version = "~> 5.0"

  bucket = "${local.name}-logs-${data.aws_caller_identity.current.account_id}"

  versioning = { enabled = "Enabled" }

  replication_configuration = {
    role = var.s3_replication_role_arn
    rules = [
      {
        id     = "replicate-logs"
        status = "Enabled"
        destination = {
          bucket        = var.s3_replication_destination_bucket_arn
          storage_class = "STANDARD_IA"
        }
      }
    ]
  }

  lifecycle_rule = [
    {
      id     = "log-retention"
      status = "Enabled"
      transition = [
        { days = 30, storage_class = "STANDARD_IA" },
        { days = 90, storage_class = "GLACIER" }
      ]
      expiration = { days = var.log_retention_days }
    }
  ]

  tags = var.tags
}

################################################################################
# File Storage - EFS (HIPAA 164.312(a)(2)(iv) - CMK encryption)
################################################################################

module "efs" {
  source  = "hipaa.compliance.tf/terraform-aws-modules/efs/aws"
  version = "~> 2.0"

  name = "${local.name}-efs"

  # HIPAA 164.312(a)(2)(iv): CMK encryption, not the default AWS-managed key
  encrypted   = true
  kms_key_arn = module.kms.key_arn

  mount_targets = {
    for idx, subnet_id in module.vpc.private_subnets :
    "az-${idx}" => { subnet_id = subnet_id }
  }

  security_group_ingress_rules = {
    vpc_ingress = {
      description = "NFS from VPC (PHI processing zone only)"
      cidr_ipv4   = var.vpc_cidr
    }
  }

  tags = var.tags
}

################################################################################
# Messaging - SQS (HIPAA 164.312(a)(2)(iv))
################################################################################

module "sqs" {
  source  = "hipaa.compliance.tf/terraform-aws-modules/sqs/aws"
  version = "~> 5.0"

  name = "${local.name}-queue"

  sqs_managed_sse_enabled    = true
  visibility_timeout_seconds = 60
  message_retention_seconds  = 1209600 # 14 days

  create_dlq = true
  dlq_name   = "${local.name}-queue-dlq"

  tags = var.tags
}

################################################################################
# Cache - ElastiCache Redis (HIPAA 164.312(d) - authentication)
################################################################################

module "elasticache" {
  source  = "hipaa.compliance.tf/terraform-aws-modules/elasticache/aws"
  version = "~> 1.0"

  replication_group_id = "${local.name}-redis"

  engine         = "redis"
  engine_version = var.redis_engine_version
  node_type      = var.redis_node_type

  # HIPAA 164.312(e)(1): encryption in transit (Redis AUTH)
  transit_encryption_enabled = true
  at_rest_encryption_enabled = true

  automatic_failover_enabled = var.environment == "prod"
  num_cache_clusters         = var.environment == "prod" ? 2 : 1

  subnet_ids = module.vpc.private_subnets

  security_group_rules = {
    vpc_ingress = { cidr_ipv4 = module.vpc.vpc_cidr_block }
  }

  tags = var.tags
}

################################################################################
# Search - OpenSearch (HIPAA 164.312(a)(1) + 164.312(b))
################################################################################

module "opensearch" {
  source  = "hipaa.compliance.tf/terraform-aws-modules/opensearch/aws"
  version = "~> 2.0"

  domain_name    = "${local.name}-search"
  engine_version = "OpenSearch_2.11"

  cluster_config = {
    instance_type            = var.opensearch_instance_type
    instance_count           = var.environment == "prod" ? 3 : 1
    dedicated_master_enabled = var.environment == "prod"
  }

  vpc_options = {
    subnet_ids = [module.vpc.private_subnets[0]]
  }

  # HIPAA 164.312(a)(2)(iv): CMK encryption at rest
  encrypt_at_rest = {
    enabled    = true
    kms_key_id = module.kms.key_arn
  }

  # HIPAA 164.312(e)(2)(ii): node-to-node encryption
  node_to_node_encryption = { enabled = true }

  # HIPAA 164.312(b): HTTPS-only and audit logs
  domain_endpoint_options = {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }

  log_publishing_options = [
    {
      log_type                 = "AUDIT_LOGS"
      cloudwatch_log_group_arn = module.cloudwatch.cloudwatch_log_group_arn
    }
  ]

  # HIPAA 164.312(a)(1): fine-grained access control
  advanced_security_options = {
    enabled                        = true
    anonymous_auth_enabled         = false
    internal_user_database_enabled = false
  }

  tags = var.tags
}

################################################################################
# Observability - CloudWatch (HIPAA 164.312(b))
################################################################################

module "cloudwatch" {
  source  = "hipaa.compliance.tf/terraform-aws-modules/cloudwatch/aws//modules/log-group"
  version = "~> 5.0"

  name              = "/app/${local.name}"
  retention_in_days = var.log_retention_days

  tags = var.tags
}

################################################################################
# Data sources
################################################################################

data "aws_caller_identity" "current" {}
