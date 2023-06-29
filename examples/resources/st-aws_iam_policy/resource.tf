resource "st-aws_iam_policy" "iam_policy" {
  policy_name     = "test-policy"
  attached_policy = ["PowerUserAccess", "AWSSupportAccess", "AWSLambdaRole", "AmazonSNSRole"]
  user_name       = "devopsuser01"
}
