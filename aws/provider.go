package aws

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awsCloudfrontClient "github.com/aws/aws-sdk-go-v2/service/cloudfront"
	awsIamClient "github.com/aws/aws-sdk-go-v2/service/iam"
	awsRoute53Client "github.com/aws/aws-sdk-go-v2/service/route53"
	awsSsoAdminClient "github.com/aws/aws-sdk-go-v2/service/ssoadmin"
)

// Wrapper of AWS clients
type awsClients struct {
	config           *awsClientsConfig
	cloudfrontClient *awsCloudfrontClient.Client
	route53Client    *awsRoute53Client.Client
	iamClient        *awsIamClient.Client
	ssoAdminClient   *awsSsoAdminClient.Client
}

type awsClientsConfig struct {
	region    string
	accessKey string
	secretKey string
}

// Ensure the implementation satisfies the expected interfaces
var (
	_ provider.Provider = &awsServicesProvider{}
)

// New is a helper function to simplify provider server
func New() provider.Provider {
	return &awsServicesProvider{}
}

type awsServicesProvider struct{}

type awsServicesProviderModel struct {
	Region    types.String `tfsdk:"region"`
	AccessKey types.String `tfsdk:"access_key"`
	SecretKey types.String `tfsdk:"secret_key"`
}

// Metadata returns the provider type name.
func (p *awsServicesProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "st-aws"
}

// Schema defines the provider-level schema for configuration data.
func (p *awsServicesProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The AWS provider is used to interact with the many resources supported by AWS. " +
			"The provider needs to be configured with the proper credentials before it can be used.",
		Attributes: map[string]schema.Attribute{
			"region": schema.StringAttribute{
				Description: "Region for AWS Services API. May also be provided via AWS_REGION environment variable.",
				Optional:    true,
			},
			"access_key": schema.StringAttribute{
				Description: "URI for AWS Services API. May also be provided via " +
					"AWS_ACCESS_KEY_ID environment variable.",
				Optional: true,
			},
			"secret_key": schema.StringAttribute{
				Description: "API key for AWS Services API. May also be provided " +
					"via AWS_SECRET_ACCESS_KEY environment variable.",
				Optional:  true,
				Sensitive: true,
			},
		},
	}
}

// Configure prepares a AWS Services API client for data sources and resources.
func (p *awsServicesProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config awsServicesProviderModel
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// If practitioner provided a configuration value for any of the
	// attributes, it must be a known value.

	if config.Region.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("region"),
			"Unknown AWS Services region",
			"The provider cannot create the AWS Services API client as there is"+
				"an unknown configuration value for the AWS Services API region."+
				"Set the value statically in the configuration, or use the AWS_REGION"+
				"environment variable.",
		)
	}

	if config.AccessKey.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("access_key"),
			"Unknown AWS Services Access Key",
			"The provider cannot create the AWS Services API client as there is "+
				"an unknown configuration value for the AWS Services API Access "+
				"Key. Set the value statically in the configuration, or use the "+
				"AWS_ACCESS_KEY_ID environment variable.",
		)
	}

	if config.SecretKey.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("secret_key"),
			"Unknown AWS Services Secret Key",
			"The provider cannot create the AWS Services API client as there is "+
				"an unknown configuration value for the AWS Services Secret key. "+
				"Set the value statically in the configuration, or use the AWS_SECRET_ACCESS_KEY "+
				"environment variable.",
		)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	// Default values to environment variables, but override
	// with Terraform configuration value if set.
	var region, accessKey, secretKey string
	if !config.Region.IsNull() {
		region = config.Region.ValueString()
	} else {
		region = os.Getenv("AWS_REGION")
	}

	if !config.AccessKey.IsNull() {
		accessKey = config.AccessKey.ValueString()
	} else {
		accessKey = os.Getenv("AWS_ACCESS_KEY_ID")
	}

	if !config.SecretKey.IsNull() {
		secretKey = config.SecretKey.ValueString()
	} else {
		secretKey = os.Getenv("AWS_SECRET_ACCESS_KEY")
	}

	// If any of the expected configuration are missing, return
	// errors with provider-specific guidance.

	if region == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("region"),
			"Missing AWS Services API region",
			"The provider cannot create the AWS Services API client as there is a "+
				"missing or empty value for the AWS Services API region. Set the "+
				"region value in the configuration or use the AWS_REGION "+
				"environment variable. If either is already set, ensure the value "+
				"is not empty.",
		)
	}

	if accessKey == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("access_key"),
			"Missing AWS Services API Access Key",
			"The provider cannot create the AWS Services API client as there is a "+
				"missing or empty value for the AWS Services API access key. Set the "+
				"access key value in the configuration or use the AWS_ACCESS_KEY_ID "+
				"environment variable. If either is already set, ensure the value "+
				"is not empty.",
		)
	}

	if secretKey == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("secret_key"),
			"Missing AWS Services Secret Key",
			"The provider cannot create the AWS Services API client as there is "+
				"a missing or empty value for the AWS Services API secret key. Set "+
				"the API secret key value in the configuration or use the AWS_SECRET_ACCESS_KEY "+
				"environment variable. If either is already set, ensure the value "+
				"is not empty.",
		)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	awsCfg, err := awsConfig.LoadDefaultConfig(
		ctx,
		awsConfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
		awsConfig.WithRegion(region),
	)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Create AWS Services API Client",
			"An unexpected error occurred when creating the AWS Services API client. "+
				"If the error is not clear, please contact the provider developers.\n"+
				"AWS Services Client Error: "+err.Error(),
		)
		return
	}

	// Initialize Clients
	cloudfrontClient := awsCloudfrontClient.NewFromConfig(awsCfg)
	route53Client := awsRoute53Client.NewFromConfig(awsCfg)
	iamClient := awsIamClient.NewFromConfig(awsCfg)
	ssoAdminClient := awsSsoAdminClient.NewFromConfig(awsCfg)

	clients := awsClients{
		config: &awsClientsConfig{
			region:    region,
			accessKey: accessKey,
			secretKey: secretKey,
		},
		cloudfrontClient: cloudfrontClient,
		route53Client:    route53Client,
		iamClient:        iamClient,
		ssoAdminClient:   ssoAdminClient,
	}

	resp.DataSourceData = clients
	resp.ResourceData = clients
}

func (p *awsServicesProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewCdnDomainDataSource,
		NewIamRolesDataSource,
		NewIamUsersDataSource,
	}
}

func (p *awsServicesProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewRoute53Resource,
		NewIamPolicyResource,
		NewIamRolePolicyResource,
		NewIamUserPolicyResource,
		NewIamPermissionSetPolicyResource,
	}
}
