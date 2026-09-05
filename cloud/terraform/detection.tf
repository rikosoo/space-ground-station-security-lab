# ---------------------------------------------------------------------------
# Detection and response tier: two Lambdas, one event bus, Security Hub as the
# finding store, CloudWatch as the metric and alarm surface.
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "detector" {
  name              = "/aws/lambda/${local.name}-detector"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.telemetry.arn
}

data "archive_file" "detector" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda/detector"
  output_path = "${path.module}/.build/detector.zip"
}

data "archive_file" "responder" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda/responder"
  output_path = "${path.module}/.build/responder.zip"
}

resource "aws_lambda_function" "detector" {
  function_name    = "${local.name}-detector"
  role             = aws_iam_role.detector.arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.detector.output_path
  source_code_hash = data.archive_file.detector.output_base64sha256
  memory_size      = var.detector_memory_mb
  timeout          = 60

  # The rule pack (src/spacelab) is shipped as a layer so that the deployed
  # detector and the offline experiments run byte-identical detection logic.
  layers = [aws_lambda_layer_version.spacelab.arn]

  environment {
    variables = {
      ACCOUNT_ID       = data.aws_caller_identity.current.account_id
      METRIC_NAMESPACE = "SpaceGroundSegment/Detection"
      RESPONSE_BUS     = aws_cloudwatch_event_bus.security.name
      SPACECRAFT_ID    = var.spacecraft_id
    }
  }

  depends_on = [aws_cloudwatch_log_group.detector]
}

resource "aws_lambda_layer_version" "spacelab" {
  layer_name          = "${local.name}-spacelab"
  filename            = "${path.module}/.build/spacelab-layer.zip"
  compatible_runtimes = ["python3.12"]

  # Build with: make layer   (see cloud/Makefile)
  lifecycle {
    ignore_changes = [filename]
  }
}

resource "aws_lambda_event_source_mapping" "telemetry" {
  event_source_arn                   = aws_kinesis_stream.telemetry.arn
  function_name                      = aws_lambda_function.detector.arn
  starting_position                  = "LATEST"
  batch_size                         = 100
  # The single most important latency knob in the whole architecture: it bounds
  # how long an event can sit in the stream before a rule ever sees it.
  maximum_batching_window_in_seconds = 2
  maximum_retry_attempts             = 3
}

resource "aws_cloudwatch_event_bus" "security" {
  name = "${local.name}-security-bus"
}

# CloudTrail management events that matter for R11, routed straight to the
# detector so that control-plane tampering is seen in seconds rather than at the
# next scheduled query.
resource "aws_cloudwatch_event_rule" "control_plane" {
  name        = "${local.name}-control-plane-tampering"
  description = "Security-relevant control-plane API calls."

  event_pattern = jsonencode({
    source      = ["aws.cloudtrail", "aws.s3", "aws.iam", "aws.kms"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "StopLogging", "DeleteTrail", "UpdateTrail", "PutBucketPolicy",
        "PutBucketAcl", "DeleteBucketPolicy", "CreateAccessKey",
        "ScheduleKeyDeletion", "DisableKey", "PutKeyPolicy"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "control_plane_to_detector" {
  rule      = aws_cloudwatch_event_rule.control_plane.name
  target_id = "detector"
  arn       = aws_lambda_function.detector.arn
}

resource "aws_lambda_permission" "events_invoke_detector" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.control_plane.arn
}

# ------------------------------------------------------------- containment ---
resource "aws_lambda_function" "responder" {
  function_name    = "${local.name}-responder"
  role             = aws_iam_role.responder.arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.responder.output_path
  source_code_hash = data.archive_file.responder.output_base64sha256
  memory_size      = 256
  timeout          = 30
  layers           = [aws_lambda_layer_version.spacelab.arn]

  environment {
    variables = {
      ACTIONS_TABLE          = aws_dynamodb_table.response_actions.name
      UPLINK_PARAMETER       = "/sgs/uplink/enabled"
      TRAIL_NAME             = aws_cloudtrail.audit.name
      QUARANTINE_POLICY_ARN  = aws_iam_policy.quarantine.arn
    }
  }
}

resource "aws_cloudwatch_event_rule" "alerts" {
  name           = "${local.name}-security-alerts"
  event_bus_name = aws_cloudwatch_event_bus.security.name

  event_pattern = jsonencode({
    source      = ["sgs.detector"]
    detail-type = ["SecurityAlert"]
    detail      = { severity = ["high", "critical"] }
  })
}

resource "aws_cloudwatch_event_target" "alerts_to_responder" {
  rule           = aws_cloudwatch_event_rule.alerts.name
  event_bus_name = aws_cloudwatch_event_bus.security.name
  target_id      = "responder"
  arn            = aws_lambda_function.responder.arn
}

resource "aws_cloudwatch_event_target" "alerts_to_analysts" {
  rule           = aws_cloudwatch_event_rule.alerts.name
  event_bus_name = aws_cloudwatch_event_bus.security.name
  target_id      = "analysts"
  arn            = aws_sns_topic.alerts.arn
}

resource "aws_lambda_permission" "events_invoke_responder" {
  statement_id  = "AllowExecutionFromSecurityBus"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.responder.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.alerts.arn
}

resource "aws_dynamodb_table" "response_actions" {
  name         = "${local.name}-response-actions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"

  attribute {
    name = "pk"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.telemetry.arn
  }
}

resource "aws_sns_topic" "alerts" {
  name              = "${local.name}-security-alerts"
  kms_master_key_id = aws_kms_key.telemetry.id
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ----------------------------------------------------------------- posture ---
resource "aws_securityhub_account" "this" {}

resource "aws_guardduty_detector" "this" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
  }
}

# --------------------------------------------------------------- telemetry ---
# An alarm on the detector's own health: a detection pipeline that stops
# producing alerts is indistinguishable from a quiet week unless it is measured.
resource "aws_cloudwatch_metric_alarm" "detector_errors" {
  alarm_name          = "${local.name}-detector-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    FunctionName = aws_lambda_function.detector.function_name
  }
}

resource "aws_cloudwatch_metric_alarm" "iterator_age" {
  alarm_name          = "${local.name}-detector-iterator-age"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "IteratorAge"
  namespace           = "AWS/Lambda"
  period              = 60
  statistic           = "Maximum"
  threshold           = 30000 # 30 s of lag is already half the detection budget
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    FunctionName = aws_lambda_function.detector.function_name
  }
}
