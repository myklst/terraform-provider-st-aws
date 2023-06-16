package aws

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awsCloudfrontClient "github.com/aws/aws-sdk-go-v2/service/cloudfront"
	awsCloudfrontTypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
)

var (
	_ datasource.DataSource              = &cdnDomainDataSource{}
	_ datasource.DataSourceWithConfigure = &cdnDomainDataSource{}
)

func NewCdnDomainDataSource() datasource.DataSource {
	return &cdnDomainDataSource{}
}

type cdnDomainDataSource struct {
	client *awsCloudfrontClient.Client
}

type cdnDomainDataSourceModel struct {
	ClientConfig *clientConfig `tfsdk:"client_config"`
	DomainName   types.String  `tfsdk:"domain_name"`
	DomainCName  types.String  `tfsdk:"domain_cname"`
	Origins      types.List    `tfsdk:"origins"`
}

type clientConfig struct {
	Region    types.String `tfsdk:"region"`
	AccessKey types.String `tfsdk:"access_key"`
	SecretKey types.String `tfsdk:"secret_key"`
}

func (d *cdnDomainDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cloudfront_domain"
}

func (d *cdnDomainDataSource) Schema(_ context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve information about a CloudFront distribution.",
		Attributes: map[string]schema.Attribute{
			"domain_name": schema.StringAttribute{
				Description: "Domain name of CDN domain.",
				Required:    true,
			},
			"domain_cname": schema.StringAttribute{
				Description: "Domain CName of CDN domain.",
				Computed:    true,
			},
			"origins": schema.ListAttribute{
				Description: "Origins of CDN domain.",
				ElementType: types.StringType,
				Computed:    true,
			},
		},
		Blocks: map[string]schema.Block{
			"client_config": schema.SingleNestedBlock{
				Description: "Config to override default client created in Provider. " +
					"This block will not be recorded in state file.",
				Attributes: map[string]schema.Attribute{
					"region": schema.StringAttribute{
						Description: "The region of the Cloudfront domains. Default to " +
							"use region configured in the provider.",
						Optional: true,
					},
					"access_key": schema.StringAttribute{
						Description: "The access key that have permissions to list " +
							"Cloudfront domains. Default to use access key configured " +
							"in the provider.",
						Optional: true,
					},
					"secret_key": schema.StringAttribute{
						Description: "The secret key that have permissions to lsit " +
							"Cloudfront domains. Default to use secret key configured " +
							"in the provider.",
						Optional: true,
					},
				},
			},
		},
	}
}

func (d *cdnDomainDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	d.client = req.ProviderData.(awsClients).cloudfrontClient
}

func (d *cdnDomainDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var plan, state *cdnDomainDataSourceModel
	diags := req.Config.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.ClientConfig == nil {
		plan.ClientConfig = &clientConfig{}
	}

	var region, accessKey, secretKey string
	initClient := false
	if !(plan.ClientConfig.Region.IsUnknown() && plan.ClientConfig.Region.IsNull()) {
		if region = plan.ClientConfig.Region.ValueString(); region != "" {
			initClient = true
		}
	}
	if !(plan.ClientConfig.AccessKey.IsUnknown() && plan.ClientConfig.AccessKey.IsNull()) {
		if accessKey = plan.ClientConfig.AccessKey.ValueString(); accessKey != "" {
			initClient = true
		}
	}
	if !(plan.ClientConfig.SecretKey.IsUnknown() && plan.ClientConfig.SecretKey.IsNull()) {
		if secretKey = plan.ClientConfig.SecretKey.ValueString(); secretKey != "" {
			initClient = true
		}
	}

	if initClient {
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			resp.Diagnostics.AddError(
				"[INTERNAL ERROR] Failed to Retrieve Client Config",
				"This is an error in provider, please contact the provider developers.\n\n"+
					"Error: "+err.Error(),
			)
			return
		}

		if region != "" {
			cfg.Region = region
		}
		if accessKey != "" && secretKey != "" {
			cfg.Credentials = credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")
		}
		d.client = awsCloudfrontClient.NewFromConfig(cfg)
	}

	domainName := plan.DomainName.ValueString()

	if domainName == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("domain_name"),
			"Missing CDN domain name",
			"Domain name must not be empty",
		)
		return
	}

	var awsCloudfrontRaw awsCloudfrontTypes.DistributionSummary
	cloudfrontMatched := false
	awsCloudfronts, err := d.client.ListDistributions(ctx, &awsCloudfrontClient.ListDistributionsInput{})

	if err != nil {
		resp.Diagnostics.AddError(
			"[API ERROR] Failed to query cloudfront domains",
			err.Error(),
		)
		return
	}
	for _, cloudfront := range awsCloudfronts.DistributionList.Items {
		if len(cloudfront.Aliases.Items) > 0 && cloudfront.Aliases.Items[0] == domainName {
			awsCloudfrontRaw = cloudfront
			cloudfrontMatched = true
		}
	}

	state = &cdnDomainDataSourceModel{
		Origins: types.ListNull(types.StringType),
	}
	if cloudfrontMatched {
		state.DomainName = types.StringValue(awsCloudfrontRaw.Aliases.Items[0])
		state.DomainCName = types.StringValue(*awsCloudfrontRaw.DomainName)
		var originsRaw []string
		for _, sourceModel := range awsCloudfrontRaw.Origins.Items {
			originsRaw = append(originsRaw, *sourceModel.DomainName)
		}
		originsList, diags := types.ListValueFrom(ctx, types.StringType, originsRaw)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		state.Origins = originsList
	}

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}
