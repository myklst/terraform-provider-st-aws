resource "st-aws_permission_set_attachment" "aws_single_sign_on" {
  permission_set_name = "test"
  instance_arn        = "ssoins-xxxxxxxxxxxxxx"
  permission_set_arn  = "arn:aws:sso:::permissionSet/ssoins-xxxxxxxxxxxxxx/ps-xxxxxxxxxxxxx"
  policy_path         = "/"
  attached_policies = [
    "AWSSupportAccess",
    "PowerUserAccess",
    "AWSBillingReadOnlyAccess",
    "ReadOnlyAccess",
  ]
}
