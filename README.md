Terraform Custom Provider for Amazon Web Service
================================================

This Terraform custom provider is designed for own use case scenario.

Supported Versions
------------------

| Terraform version | minimum provider version |maxmimum provider version
| ---- | ---- | ----|
| >= 1.3.x	| 0.1.0	| latest |

Requirements
------------

-	[Terraform](https://www.terraform.io/downloads.html) 1.3.x
-	[Go](https://golang.org/doc/install) 1.19 (to build the provider plugin)

Local Installation
------------------

1. Run `make install-local-custom-provider` to install the provider under ~/.terraform.d/plugins.

2. The provider source should be change to the path that configured in the *Makefile*:

    ```
    terraform {
      required_providers {
        st-aws = {
          source = "example.local/myklst/st-aws"
        }
      }
    }

    provider "st-aws" {}
    ```

Why Custom Provider
-------------------

This custom provider exists due to some of the resources and data sources in the
official AWS Terraform provider may not fulfill the requirements of some scenario.
The reason behind every resources and data sources are stated as below:

### Resources

- **st-aws_route53_traffic_policy**

  The resource
  [*aws_route53_traffic_policy*](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route53_traffic_policy)
  in official AWS Terraform provider does not support in-place update of the arguments
  *document* and *comment*.

- **st-aws_iam_policy**

  This resource is designed to handle policy content that exceeds the limit of 6144 characters.
  It provides functionality to create policies by splitting the content into smaller segments that fit within the limit,
  enabling the management and combination of these segments to form the complete policy. Finally, the policy will be attached to the relevant user.

### Data Sources

- **st-aws_cloudfront_domain**

  - Official AWS Terraform provider does not support querying AWS Cloudfront distributions using domain name through
    [*aws_cloudfront_distribution*](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/cloudfront_distribution).

  - Added client_config block to allow overriding the Provider configuration.

- **st-aws_iam_users**

  The data source
  [*aws_iam_users*](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_users)
  in official AWS Terraform provider does not support querying AWS IAM users using tags.

References
----------

- Terraform website: https://www.terraform.io
- Terraform Plugin Framework: https://developer.hashicorp.com/terraform/tutorials/providers-plugin-framework
- AWS official Terraform provider: https://github.com/hashicorp/terraform-provider-aws
