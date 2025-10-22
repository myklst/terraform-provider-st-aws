resource "st-aws_iam_user_policy" "iam_policy" {
  user_name = "devopsuser01"
  attached_policies = [
    "IAMFullAccess",
    "PowerUserAccess",
    "AWSSupportAccess",
  ]
}
