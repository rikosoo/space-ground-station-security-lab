terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = "space-ground-station-security-lab"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}
