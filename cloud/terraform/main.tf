# ---------------------------------------------------------------------------
# Ground-segment security data plane.
#
#   ground station / API  ->  Kinesis  ->  detector Lambda  ->  Security Hub
#                              |                |                    |
#                              v                v                    v
#                         S3 archive      CloudWatch metrics   EventBridge bus
#                                                                    |
#                                                              responder Lambda
#
# CloudTrail supplies the cloud-side half of the same picture: management events
# reach the detector through EventBridge, S3 data events reach it through the
# trail's own log stream.
# ---------------------------------------------------------------------------

locals {
  name = "sgs-${var.environment}"
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# --------------------------------------------------------------- ingestion ---
resource "aws_kinesis_stream" "telemetry" {
  name             = "${local.name}-telemetry"
  retention_period = 24

  stream_mode_details {
    stream_mode = "ON_DEMAND"
  }

  encryption_type = "KMS"
  kms_key_id      = aws_kms_key.telemetry.id
}

resource "aws_kms_key" "telemetry" {
  description             = "Encrypts ground-segment telemetry at rest and in the stream."
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "telemetry" {
  name          = "alias/${local.name}-telemetry"
  target_key_id = aws_kms_key.telemetry.key_id
}

# ----------------------------------------------------------------- archive ---
resource "aws_s3_bucket" "archive" {
  bucket = "${local.name}-telemetry-archive-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_public_access_block" "archive" {
  bucket                  = aws_s3_bucket.archive.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "archive" {
  bucket = aws_s3_bucket.archive.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "archive" {
  bucket = aws_s3_bucket.archive.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.telemetry.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "archive" {
  bucket = aws_s3_bucket.archive.id

  rule {
    id     = "transition-cold"
    status = "Enabled"
    filter {}

    transition {
      days          = var.telemetry_retention_days
      storage_class = "GLACIER_IR"
    }
  }
}

# ------------------------------------------------------------------ audit ----
resource "aws_s3_bucket" "trail" {
  bucket        = "${local.name}-audit-${data.aws_caller_identity.current.account_id}"
  force_destroy = false
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail_bucket.json
}

data "aws_iam_policy_document" "trail_bucket" {
  statement {
    sid     = "AWSCloudTrailAclCheck"
    actions = ["s3:GetBucketAcl"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    resources = [aws_s3_bucket.trail.arn]
  }

  statement {
    sid     = "AWSCloudTrailWrite"
    actions = ["s3:PutObject"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_cloudtrail" "audit" {
  name                          = "${local.name}-audit"
  s3_bucket_name                = aws_s3_bucket.trail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  # Data events on the telemetry archive are what make exfiltration visible;
  # without this block, attack A5 leaves no trace in the audit log at all.
  advanced_event_selector {
    name = "telemetry-archive-data-events"

    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }
    field_selector {
      field       = "resources.ARN"
      starts_with = ["${aws_s3_bucket.archive.arn}/"]
    }
  }

  depends_on = [aws_s3_bucket_policy.trail]
}
