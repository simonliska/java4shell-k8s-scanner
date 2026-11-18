terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    http = {
      source  = "hashicorp/http"
      version = "~> 3.4"
    }
  }
}

provider "aws" {
  region = var.region

  # Every resource gets these tags, so leftovers are easy to find:
  #   aws resourcegroupstaggingapi get-resources --tag-filters Key=Project,Values=java4shell-lab
  default_tags {
    tags = {
      Project   = "java4shell-lab"
      ManagedBy = "terraform"
    }
  }
}
