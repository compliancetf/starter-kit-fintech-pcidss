################################################################################
# PCI DSS v4.0 + SOC 2 Compliance Starter Kit - Fintech
#
# Pre-composed infrastructure for fintech companies (payment platforms,
# neobanks, BNPL) preparing for PCI DSS v4.0 certification.
# All modules source from the compliance.tf registry and enforce PCI DSS
# and SOC 2 controls at terraform plan time.
#
# PCI DSS 4.0 requirements enforced automatically:
#   2.2   - System components configured to reduce vulnerabilities
#   3.4.1 - PAN rendered unreadable (KMS encryption at rest)
#   4.2.1 - Strong cryptography during transmission (TLS 1.2+)
#   6.4.1 - Web-facing apps protected against attacks (WAF)
#   10.2  - Audit logs implemented
#   10.3  - Audit log entries with required information
################################################################################

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terraform"
      Compliance  = "pcidss"
    }
  }
}

# CloudFront WAF must reside in us-east-1 regardless of primary region
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

locals {
  name = "${var.project_name}-${var.environment}"
}

################################################################################
# Network
################################################################################

module "vpc" {
  source  = "pcidss.compliance.tf/terraform-aws-modules/vpc/aws"
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

  # PCI DSS 10.2: VPC flow logs for network traffic audit trail
  enable_flow_log                      = true
  create_flow_log_cloudwatch_log_group = true

  tags = var.tags
}

################################################################################
# Load Balancer
################################################################################

module "alb" {
  source  = "pcidss.compliance.tf/terraform-aws-modules/alb/aws"
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
      # PCI DSS 4.2.1: TLS 1.2 minimum, TLS 1.3 preferred
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
# CloudFront CDN (PCI DSS 4.2.1, 6.4.1)
################################################################################

module "cloudfront" {
  source  = "pcidss.compliance.tf/terraform-aws-modules/cloudfront/aws"
  version = "~> 6.0"

  enabled         = true
  is_ipv6_enabled = true
  price_class     = "PriceClass_100"
  comment         = "${local.name} CDN - PCI DSS TLS enforcement"

  # PCI DSS 4.2.1: TLS 1.2 minimum at CDN edge
  viewer_certificate = {
    acm_certificate_arn      = module.acm_us_east_1.acm_certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  restrictions = {
    geo_restriction = {
      restriction_type = "none"
    }
  }

  origin = {
    alb = {
      domain_name = module.alb.dns_name
      custom_origin_config = {
        http_port  = 80
        https_port = 443
        # PCI DSS 4.2.1: HTTPS-only to origin
        origin_protocol_policy = "https-only"
        origin_ssl_protocols   = ["TLSv1.2"]
      }
    }
  }

  default_cache_behavior = {
    target_origin_id = "alb"
    # PCI DSS 4.2.1: redirect all HTTP to HTTPS
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true

    forwarded_values = {
      query_string = true
      cookies      = { forward = "all" }
    }
  }

  # PCI DSS 10.2: CloudFront access logging
  logging_config = {
    bucket = module.s3_bucket_logs.s3_bucket_bucket_domain_name
    prefix = "cloudfront/"
  }

  # PCI DSS 6.4.1: WAF attached (global scope, us-east-1)
  web_acl_id = module.waf_global.web_acl_arn

  tags = var.tags
}

# ACM certificate in us-east-1 (required for CloudFront)
module "acm_us_east_1" {
  source  = "pcidss.compliance.tf/terraform-aws-modules/acm/aws"
  version = "~> 6.0"

  providers = {
    aws = aws.us_east_1
  }

  domain_name = var.domain_name
  zone_id     = var.route53_zone_id

  validation_method = "DNS"

  subject_alternative_names = [
    "*.${var.domain_name}",
    "cdn.${var.domain_name}",
  ]

  wait_for_validation = true

  tags = var.tags
}

################################################################################
# WAF - Regional (ALB association, PCI DSS 6.4.1)
################################################################################

module "waf" {
  source  = "pcidss.compliance.tf/terraform-aws-modules/wafv2/aws"
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
# WAF - Global (CloudFront, us-east-1, PCI DSS 6.4.1)
################################################################################

module "waf_global" {
  source  = "pcidss.compliance.tf/terraform-aws-modules/wafv2/aws"
  version = "~> 1.0"

  providers = {
    aws = aws.us_east_1
  }

  name  = "${local.name}-waf-global"
  scope = "CLOUDFRONT"

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
        metric_name                = "${local.name}-cf-common-rules"
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
        metric_name                = "${local.name}-cf-bad-inputs"
        sampled_requests_enabled   = true
      }
    }
  }

  tags = var.tags
}

################################################################################
# Certificate - Regional (for ALB)
################################################################################

module "acm" {
  source  = "pcidss.compliance.tf/terraform-aws-modules/acm/aws"
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
# KMS - CMK for CDE encryption (PCI DSS 3.4.1)
################################################################################

module "kms" {
  source  = "pcidss.compliance.tf/terraform-aws-modules/kms/aws"
  version = "~> 4.0"

  description = "KMS CMK for ${local.name} CDE encryption (PCI DSS 3.4.1)"
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

  aliases = ["${local.name}/cde"]

  tags = var.tags
}

################################################################################
# Compute - EKS (CDE scope)
################################################################################

module "eks" {
  source  = "pcidss.compliance.tf/terraform-aws-modules/eks/aws"
  version = "= 21.17.1"

  name               = local.name
  kubernetes_version = var.eks_cluster_version

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  endpoint_public_access  = false
  endpoint_private_access = true

  cloudwatch_log_group_kms_key_id = module.kms.key_arn

  # PCI DSS 3.4.1: KMS encryption for Kubernetes secrets
  encryption_config = {
    provider_key_arn = module.kms.key_arn
    resources        = ["secrets"]
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
# Compute - Lambda (VPC-attached, CDE scope, PCI DSS 1.3)
################################################################################

module "lambda" {
  source  = "pcidss.compliance.tf/terraform-aws-modules/lambda/aws"
  version = "~> 8.0"

  function_name = "${local.name}-function"
  description   = "Application function - VPC-attached for CDE network controls"
  runtime       = var.lambda_runtime
  handler       = "index.handler"

  # PCI DSS 1.3: Lambda in private subnet for CDE network isolation
  vpc_subnet_ids         = module.vpc.private_subnets
  vpc_security_group_ids = [module.vpc.default_security_group_id]

  # PCI DSS 3.4.1: KMS encryption for environment variables
  kms_key_arn = module.kms.key_arn

  # PCI DSS 10.2: CloudWatch log group encryption at rest
  cloudwatch_logs_kms_key_id = module.kms.key_arn

  dead_letter_target_arn = module.sqs.dead_letter_queue_arn

  create_package = false

  # Package source: reference an existing zip in S3 (deploy separately)
  s3_existing_package = {
    bucket = module.s3_bucket_data.s3_bucket_id
    key    = "lambda/${local.name}-function.zip"
  }

  tags = var.tags
}

################################################################################
# Compute - EC2 (IMDSv2, private, CDE scope, PCI DSS 2.2)
################################################################################

resource "aws_iam_role" "ec2_worker" {
  name = "${local.name}-worker-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "ec2_worker_ssm" {
  role       = aws_iam_role.ec2_worker.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2_worker" {
  name = "${local.name}-worker-profile"
  role = aws_iam_role.ec2_worker.name

  tags = var.tags
}

module "ec2_instance" {
  source  = "pcidss.compliance.tf/terraform-aws-modules/ec2-instance/aws"
  version = "~> 6.0"

  name = "${local.name}-worker"

  instance_type               = var.ec2_instance_type
  ami                         = data.aws_ami.amazon_linux_2.id
  subnet_id                   = module.vpc.private_subnets[0]
  # PCI DSS 2.2: no public IP for CDE components
  associate_public_ip_address = false

  # PCI DSS 2.2: IMDSv2 required, IMDSv1 disabled
  metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  # PCI DSS 8: IAM instance profile - no shared credentials
  iam_instance_profile = aws_iam_instance_profile.ec2_worker.name

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
# Database - Aurora PostgreSQL (CDE scope, PCI DSS 3.4.1)
################################################################################

module "rds_aurora" {
  source  = "pcidss.compliance.tf/terraform-aws-modules/rds-aurora/aws"
  version = "~> 10.0"

  name            = "${local.name}-db"
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
# DynamoDB (PCI DSS 3.4.1 - KMS encryption at rest)
################################################################################

module "dynamodb" {
  source  = "pcidss.compliance.tf/terraform-aws-modules/dynamodb-table/aws"
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
# Cache - ElastiCache Redis (PCI DSS 4.2.1 - encrypted in transit)
################################################################################

module "elasticache" {
  source  = "pcidss.compliance.tf/terraform-aws-modules/elasticache/aws"
  version = "~> 1.0"

  replication_group_id = "${local.name}-redis"

  engine         = "redis"
  engine_version = var.redis_engine_version
  node_type      = var.redis_node_type

  # PCI DSS 4.2.1: encryption in transit required
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
# Storage - S3 data (PCI DSS 3.4.1 + 3.5)
################################################################################

module "s3_bucket_data" {
  source  = "pcidss.compliance.tf/terraform-aws-modules/s3-bucket/aws"
  version = "~> 5.0"

  bucket = "${local.name}-data-${data.aws_caller_identity.current.account_id}"

  versioning = { enabled = "Enabled", mfa_delete = "Enabled" }

  logging = {
    target_bucket = module.s3_bucket_logs.s3_bucket_id
    target_prefix = "s3/data/"
  }

  lifecycle_rule = [
    {
      id     = "transition-to-ia"
      status = "Enabled"
      transition = [{ days = 90, storage_class = "STANDARD_IA" }]
    }
  ]

  replication_configuration = {
    role = var.s3_replication_role_arn
    rules = [
      {
        id     = "replicate-all"
        status = "Enabled"
        destination = {
          bucket        = var.s3_replication_destination_bucket_arn
          storage_class = "STANDARD"
        }
      }
    ]
  }

  tags = var.tags
}

################################################################################
# Storage - S3 logs
################################################################################

module "s3_bucket_logs" {
  source  = "pcidss.compliance.tf/terraform-aws-modules/s3-bucket/aws"
  version = "~> 5.0"

  bucket = "${local.name}-logs-${data.aws_caller_identity.current.account_id}"

  versioning = { enabled = "Enabled", mfa_delete = "Enabled" }

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
# Messaging - SQS
################################################################################

module "sqs" {
  source  = "pcidss.compliance.tf/terraform-aws-modules/sqs/aws"
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
# Search - OpenSearch (VPC-only, audit logs, PCI DSS 10.2 + 10.3)
################################################################################

module "opensearch" {
  source  = "pcidss.compliance.tf/terraform-aws-modules/opensearch/aws"
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

  # PCI DSS 3.4.1: encryption at rest with CMK
  encrypt_at_rest = {
    enabled    = true
    kms_key_id = module.kms.key_arn
  }

  # PCI DSS 4.2.1: node-to-node encryption
  node_to_node_encryption = { enabled = true }

  # PCI DSS 10.3: HTTPS-only endpoint
  domain_endpoint_options = {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }

  # PCI DSS 10.2 + 10.3: audit logs
  log_publishing_options = [
    {
      log_type                 = "AUDIT_LOGS"
      cloudwatch_log_group_arn = module.cloudwatch.cloudwatch_log_group_arn
    }
  ]

  # PCI DSS 7: fine-grained access control
  advanced_security_options = {
    enabled                        = true
    anonymous_auth_enabled         = false
    internal_user_database_enabled = false
  }

  tags = var.tags
}

################################################################################
# Observability - CloudWatch
################################################################################

module "cloudwatch" {
  source  = "pcidss.compliance.tf/terraform-aws-modules/cloudwatch/aws//modules/log-group"
  version = "~> 5.0"

  name              = "/app/${local.name}"
  retention_in_days = var.log_retention_days

  tags = var.tags
}

################################################################################
# Data sources
################################################################################

data "aws_caller_identity" "current" {}
