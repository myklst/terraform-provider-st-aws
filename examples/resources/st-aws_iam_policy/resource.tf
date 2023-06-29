resource "st-aws_iam_policy" "iam_policy" {
  policy_name       = "test-policy"
  attached_policies = ["PowerUserAccess", "AWSSupportAccess", "AWSLambdaRole", "AmazonSNSRole"]
  user_name         = "devopsuser01"
}
