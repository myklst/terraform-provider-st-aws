resource "st-aws_iam_policy" "iam_policy" {
  attached_policies = ["PowerUserAccess", "AWSSupportAccess", "AWSLambdaRole", "AmazonSNSRole"]
  user_name         = "devopsuser01"
}
