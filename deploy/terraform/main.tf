# Aurora Pay production edge.
#
# The load balancer, its TLS policy, and the KMS keys that wrap the card-vault
# data key. Everything else is in the platform repository.

terraform {
  required_version = ">= 1.7"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
  }
}

variable "environment" {
  type    = string
  default = "production"
}

resource "aws_acm_certificate" "api" {
  domain_name       = "api.aurorapay.example"
  validation_method = "DNS"

  # RSA rather than EC: the acquirer's client library rejects EC leaf
  # certificates, and the same certificate fronts both interfaces.
  key_algorithm = "RSA_2048"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.edge.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.api.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}

# The partner listener still has to accept TLS 1.2 with a CBC suite. Separate
# listener, separate policy, so the merchant API above is unaffected.
resource "aws_lb_listener" "partners" {
  load_balancer_arn = aws_lb.edge.arn
  port              = 8443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn   = aws_acm_certificate.partners.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}

resource "aws_acm_certificate" "partners" {
  domain_name       = "partners.aurorapay.example"
  validation_method = "DNS"
  key_algorithm     = "RSA_2048"
}

# The card vault data key is wrapped by this CMK and unwrapped at pod start.
resource "aws_kms_key" "card_vault" {
  description              = "Aurora card vault data-key wrapping key"
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  enable_key_rotation      = true
  deletion_window_in_days  = 30
}

# Signing key for outbound webhooks. Asymmetric so merchants verify with the
# public half and we never distribute a shared secret.
resource "aws_kms_key" "webhook_signing" {
  description              = "Aurora outbound webhook signing key"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "RSA_3072"
  deletion_window_in_days  = 30
}

resource "aws_lb" "edge" {
  name               = "aurora-edge"
  load_balancer_type = "application"
  internal           = false
  idle_timeout       = 60
}

resource "aws_lb_target_group" "api" {
  name        = "aurora-api"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"

  health_check {
    path                = "/healthz"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 10
  }
}
