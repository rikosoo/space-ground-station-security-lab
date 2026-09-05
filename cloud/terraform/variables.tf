variable "region" {
  description = "AWS region hosting the ground-segment security stack."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment name; used as a resource-name prefix."
  type        = string
  default     = "lab"
}

variable "spacecraft_id" {
  description = "Identifier of the spacecraft this stack protects."
  type        = string
  default     = "SAT-ALPHA-1"
}

variable "telemetry_retention_days" {
  description = "Retention of raw telemetry in the hot archive before transition."
  type        = number
  default     = 90
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention. Kept short on purpose: the durable copy lives in S3."
  type        = number
  default     = 30
}

variable "alert_email" {
  description = "Address subscribed to the analyst notification topic."
  type        = string
  default     = ""
}

variable "detector_memory_mb" {
  description = "Memory for the streaming detector Lambda; drives both latency and cost."
  type        = number
  default     = 512
}
