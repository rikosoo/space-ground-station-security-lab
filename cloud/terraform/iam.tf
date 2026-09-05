# Least-privilege roles. The detector may read the stream and write findings;
# it has no permission to change anything. Only the responder can act, and only
# through the narrow set of reversible containment actions.

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "detector" {
  name               = "${local.name}-detector"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "detector" {
  statement {
    sid = "ReadTelemetryStream"
    actions = [
      "kinesis:GetRecords", "kinesis:GetShardIterator",
      "kinesis:DescribeStream", "kinesis:DescribeStreamSummary",
      "kinesis:ListShards", "kinesis:SubscribeToShard"
    ]
    resources = [aws_kinesis_stream.telemetry.arn]
  }

  statement {
    sid       = "DecryptTelemetry"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = [aws_kms_key.telemetry.arn]
  }

  statement {
    sid       = "PublishFindings"
    actions   = ["securityhub:BatchImportFindings"]
    resources = ["*"]
  }

  statement {
    sid       = "PublishMetrics"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["SpaceGroundSegment/Detection"]
    }
  }

  statement {
    sid       = "EmitAlerts"
    actions   = ["events:PutEvents"]
    resources = [aws_cloudwatch_event_bus.security.arn]
  }

  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.detector.arn}:*"]
  }
}

resource "aws_iam_role_policy" "detector" {
  role   = aws_iam_role.detector.id
  policy = data.aws_iam_policy_document.detector.json
}

resource "aws_iam_role" "responder" {
  name               = "${local.name}-responder"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "responder" {
  statement {
    sid       = "ContainIdentities"
    actions   = ["cognito-idp:AdminUserGlobalSignOut", "iam:AttachUserPolicy"]
    resources = ["*"]
  }

  statement {
    sid       = "QuarantineUplink"
    actions   = ["ssm:PutParameter"]
    resources = ["arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/sgs/*"]
  }

  statement {
    sid       = "RestoreAuditTrail"
    actions   = ["cloudtrail:StartLogging"]
    resources = [aws_cloudtrail.audit.arn]
  }

  statement {
    sid       = "RecordActions"
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.response_actions.arn]
  }

  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:*:*:*"]
  }
}

resource "aws_iam_role_policy" "responder" {
  role   = aws_iam_role.responder.id
  policy = data.aws_iam_policy_document.responder.json
}

# Attached to a compromised principal during containment: an explicit deny that
# overrides every allow the principal otherwise has on mission data.
resource "aws_iam_policy" "quarantine" {
  name        = "${local.name}-quarantine"
  description = "Explicit deny applied to a contained principal."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Deny"
      Action   = ["s3:*", "kinesis:*", "execute-api:Invoke"]
      Resource = "*"
    }]
  })
}
