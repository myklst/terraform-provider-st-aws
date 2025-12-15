####################################
# Permission Set
####################################
resource "st-aws_iam_policy_v2" "permission_set" {
  permission_set {
    permission_set_name = "example-policy"
    instance_arn        = "ssoins-xxxxxxxxxxxxxx"
    permission_set_arn  = "arn:aws:sso:::permissionSet/ssoins-xxxxxxxxxxxxxx/ps-xxxxxxxxxxxxx"
  }

  attached_policies = [
    "AWSSupportAccess",
    "PowerUserAccess",
    "AWSBillingReadOnlyAccess",
    "ReadOnlyAccess",
  ]
}

####################################
# Role
####################################
resource "st-aws_iam_policy_v2" "role" {
  role {
    role_name = "example-role"
  }

  attached_policies = [
    "AWSSupportAccess",
    "PowerUserAccess",
    "AWSBillingReadOnlyAccess",
    "ReadOnlyAccess",
  ]
}


####################################
# User
####################################
resource "st-aws_iam_policy_v2" "User" {
  user {
    user_name = "example-user"
  }

  attached_policies = [
    "AWSSupportAccess",
    "PowerUserAccess",
    "AWSBillingReadOnlyAccess",
    "ReadOnlyAccess",
  ]
}

####################################
# Create Policy Only
####################################
resource "st-aws_iam_policy_v2" "Create_Policy_Only" {
  policy_name = "test"

  attached_policies = [
    "AWSSupportAccess",
    "PowerUserAccess",
    "AWSBillingReadOnlyAccess",
    "ReadOnlyAccess",
  ]
}
