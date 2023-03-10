package aws

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

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
	DomainName  types.String `tfsdk:"domain_name"`
	DomainCName types.String `tfsdk:"domain_cname"`
	Origins     types.List   `tfsdk:"origins"`
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
	}
}

func (d *cdnDomainDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	d.client = req.ProviderData.(awsClients).cloudfrontClient
}

func (d *cdnDomainDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state cdnDomainDataSourceModel
	diags := req.Config.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	domainName := state.DomainName.ValueString()

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
		if cloudfront.Aliases.Items[0] == domainName {
			awsCloudfrontRaw = cloudfront
			cloudfrontMatched = true
		}
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
