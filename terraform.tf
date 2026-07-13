terraform {
  required_version = ">= 1.9.0, < 2.0.0"

  required_providers {
    msgraph = {
      source  = "Microsoft/msgraph"
      version = ">= 0.1.0, < 1.0.0"
    }
  }
}
