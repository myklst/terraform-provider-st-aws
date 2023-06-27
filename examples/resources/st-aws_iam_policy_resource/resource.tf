resource "st-aws_iam_policy" "iam_policy" {
  policy_name     = "test-policy"
  policy_document = "[\"CloudSearchFullAccess\",\"PowerUserAccess\",\"ReadOnlyAccess\",\"AdministratorAccess\"]"
  user_name       = "devopsuser01"
}
