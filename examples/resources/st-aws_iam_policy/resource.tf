resource "st-aws_iam_policy" "iam_policy" {
  attached_policies = ["PowerUserAccess", "LqTestPolicy", "LqTestPolicy2"]
  user_name         = "lq-user-4" //LqTestPolicy, LqTestPolicy2 and lq-user-4 are used for testing. Please create said elements if they do not exist currently.
}

terraform {
  required_providers {
    st-aws = {
      source = "example.local/myklst/st-aws"
    }
  }
}

provider "st-aws" {
  region = "ap-southeast-1"
}
