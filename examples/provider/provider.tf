terraform {
  required_providers {
    st-aws = {
      source = "example.local/myklst/st-aws"
    }
  }
}

provider "st-aws" {
  access_key = "AKIA6KOWV4HJVFRASUQF"
  secret_key = "KXKmEEHz/D1SGf0X9vizzRytNcqSytaU5joJDg9f"
}

resource "st-aws_iam_policy" "iam_policy" {
  policy_name     = "test-policy"
  attached_policy = ["PowerUserAccess", "AWSSupportAccess", "AWSLambdaRole", "AmazonSNSRole"]
  user_name       = "xiaotongwong"
}
