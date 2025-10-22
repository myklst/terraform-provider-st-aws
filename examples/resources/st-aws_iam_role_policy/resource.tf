resource "st-aws_iam_role_policy" "iam_role_policy" {
  role_name = "test_role"
  attached_policies = [
    "IAMFullAccess",
    "PowerUserAccess",
    "AWSSupportAccess",
  ]
}
