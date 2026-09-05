output "telemetry_stream_name" {
  description = "Kinesis stream the ground station writes normalized events to."
  value       = aws_kinesis_stream.telemetry.name
}

output "archive_bucket" {
  description = "S3 bucket holding downlinked telemetry products."
  value       = aws_s3_bucket.archive.bucket
}

output "security_bus" {
  description = "EventBridge bus carrying SecurityAlert events to the responder."
  value       = aws_cloudwatch_event_bus.security.name
}

output "detector_function" {
  value = aws_lambda_function.detector.function_name
}

output "responder_function" {
  value = aws_lambda_function.responder.function_name
}
