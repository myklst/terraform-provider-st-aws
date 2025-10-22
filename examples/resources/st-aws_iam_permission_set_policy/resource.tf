resource "st-aws_iam_permission_set_policy" "permission_set_policy" {
  policy_name = "example-policy"
  attached_policies = [
    "IAMFullAccess",
    "PowerUserAccess",
    "AWSSupportAccess",
  ]
  instance_arn       = "abc-1234556"
  permission_set_arn = "abc-1234556"
}
