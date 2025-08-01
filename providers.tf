terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "6.5.0"
    }
    random = {
      source = "hashicorp/random"
      version = "~> 3.1"
    }
  }
}

provider "aws" {}

provider "random" {}