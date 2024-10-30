package aws

import (
	"context"
	"time"

	awsIAMClient "github.com/aws/aws-sdk-go-v2/service/iam"
	awsTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/cenkalti/backoff"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &iamRolesDataSource{}
	_ datasource.DataSourceWithConfigure = &iamRolesDataSource{}
)

func NewIamRolesDataSource() datasource.DataSource {
	return &iamRolesDataSource{}
}

type iamRolesDataSource struct {
	client *awsIAMClient.Client
}

type iamRolesDataSourceModel struct {
	Tags  types.Map        `tfsdk:"tags"`
	Roles []*iamRoleDetail `tfsdk:"roles"`
}

type iamRoleDetail struct {
	Arn                      types.String `tfsdk:"arn"`
	CreateDate               types.String `tfsdk:"create_date"`
	Path                     types.String `tfsdk:"path"`
	RoleId                   types.String `tfsdk:"role_id"`
	RoleName                 types.String `tfsdk:"role_name"`
	AssumeRolePolicyDocument types.String `tfsdk:"assume_role_policy_document"`
	Description              types.String `tfsdk:"description"`
	MaxSessionDuration       types.Int64  `tfsdk:"max_session_duration"`
	Tags                     types.Map    `tfsdk:"tags"`
}

func (d *iamRolesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_iam_roles"
}

func (d *iamRolesDataSource) Schema(_ context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve list of IAM roles with attached tags.",
		Attributes: map[string]schema.Attribute{
			"tags": schema.MapAttribute{
				Description: "Filter by map of tags assigned to the IAM role.",
				ElementType: types.StringType,
				Optional:    true,
			},
			"roles": schema.ListNestedAttribute{
				Description: "List of IAM roles.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"arn": schema.StringAttribute{
							Description: "The Amazon Resource Name (ARN) that identifies the role.",
							Computed:    true,
						},
						"create_date": schema.StringAttribute{
							Description: "The date and time, in ISO 8601 date-time string format, when the role was created.",
							Computed:    true,
						},
						"path": schema.StringAttribute{
							Description: "The path to the role.",
							Computed:    true,
						},
						"role_id": schema.StringAttribute{
							Description: "The stable and unique string identifying the role.",
							Computed:    true,
						},
						"role_name": schema.StringAttribute{
							Description: "The friendly name identifying the role.",
							Computed:    true,
						},
						"assume_role_policy_document": schema.StringAttribute{
							Description: "The policy that grants an entity permission to assume the role.",
							Computed:    true,
						},
						"description": schema.StringAttribute{
							Description: "A description of the role that you provide.",
							Computed:    true,
						},
						"max_session_duration": schema.Int64Attribute{
							Description: "The maximum session duration (in seconds) for the specified role.",
							Computed:    true,
						},
						"tags": schema.MapAttribute{
							Description: "A list of tags that are associated with the role.",
							ElementType: types.StringType,
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

func (r *iamRolesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, _ *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(awsClients).iamClient
}

func (d *iamRolesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var plan *iamRolesDataSourceModel
	getPlanDiags := req.Config.Get(ctx, &plan)
	resp.Diagnostics.Append(getPlanDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
	state := &iamRolesDataSourceModel{}
	state.Roles = []*iamRoleDetail{}

	inputTags := make(map[string]string)
	if !(plan.Tags.IsUnknown() && plan.Tags.IsNull()) {
		state.Tags = plan.Tags
		// Convert from Terraform map type to Go map type
		convertTagsDiags := plan.Tags.ElementsAs(ctx, &inputTags, false)
		resp.Diagnostics.Append(convertTagsDiags...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	var iamRolesList []awsTypes.Role
	listRolesFunc := func() error {
		// Init variable iamRolesList to solve redundant values in backoff retry.
		iamRolesList = []awsTypes.Role{}
		listRolesInput := &awsIAMClient.ListRolesInput{}
		for {
			iamRoles, err := d.client.ListRoles(ctx, listRolesInput)
			if err != nil {
				if _t, ok := err.(awserr.Error); ok {
					if isAbleToRetry(_t.Code()) {
						return err
					} else {
						return backoff.Permanent(err)
					}
				} else {
					return backoff.Permanent(err)
				}
			}
			iamRolesList = append(iamRolesList, iamRoles.Roles...)
			if !iamRoles.IsTruncated {
				break
			}
			listRolesInput.Marker = iamRoles.Marker
		}
		return nil
	}

	listRolesBackoff := backoff.NewExponentialBackOff()
	listRolesBackoff.MaxElapsedTime = 1 * time.Minute
	err := backoff.Retry(listRolesFunc, listRolesBackoff)
	if err != nil {
		resp.Diagnostics.AddError(
			"[API ERROR] Failed to List IAM Roles",
			err.Error(),
		)
		return
	}

iamRolesLoop:
	for _, iamRole := range iamRolesList {
		var iamRoleTagsList []awsTypes.Tag
		listRoleTagsFunc := func() error {
			// Init variable iamRoleTagsList to solve redundant values in backoff retry.
			iamRoleTagsList = []awsTypes.Tag{}
			listRoleTagsInput := &awsIAMClient.ListRoleTagsInput{
				RoleName: iamRole.RoleName,
			}
			for {
				iamRoleTags, err := d.client.ListRoleTags(ctx, listRoleTagsInput)
				if err != nil {
					if _t, ok := err.(awserr.Error); ok {
						if isAbleToRetry(_t.Code()) {
							return err
						} else {
							return backoff.Permanent(err)
						}
					} else {
						return backoff.Permanent(err)
					}
				}
				iamRoleTagsList = append(iamRoleTagsList, iamRoleTags.Tags...)
				if !iamRoleTags.IsTruncated {
					break
				}
				listRoleTagsInput.Marker = iamRoleTags.Marker
			}
			return nil
		}

		listRoleTagsBackoff := backoff.NewExponentialBackOff()
		listRoleTagsBackoff.MaxElapsedTime = 1 * time.Minute
		err := backoff.Retry(listRoleTagsFunc, listRoleTagsBackoff)
		if err != nil {
			resp.Diagnostics.AddError(
				"[API ERROR] Failed to List IAM Role's Tags",
				err.Error(),
			)
			return
		}

	matchRoleTagsLoop:
		for key, value := range inputTags {
			for _, iamRoleTag := range iamRoleTagsList {
				if *iamRoleTag.Key == key && *iamRoleTag.Value == value {
					// When the tag is found, continue to next tag.
					continue matchRoleTagsLoop
				}
			}
			// When a pair of tag is not matched, continue to next role.
			continue iamRolesLoop
		}

		stateRole := &iamRoleDetail{
			Arn:                      types.StringValue(*iamRole.Arn),
			CreateDate:               types.StringValue(iamRole.CreateDate.String()),
			Path:                     types.StringValue(*iamRole.Path),
			RoleId:                   types.StringValue(*iamRole.RoleId),
			RoleName:                 types.StringValue(*iamRole.RoleName),
			AssumeRolePolicyDocument: types.StringValue(*iamRole.AssumeRolePolicyDocument),
			MaxSessionDuration:       types.Int64Value(int64(*iamRole.MaxSessionDuration)),
		}
		if iamRole.Description != nil {
			stateRole.Description = types.StringValue(*iamRole.Description)
		}
		stateRoleTags := make(map[string]attr.Value)
		for _, iamRoleTag := range iamRoleTagsList {
			stateRoleTags[*iamRoleTag.Key] = types.StringValue(*iamRoleTag.Value)
		}
		stateRole.Tags = types.MapValueMust(types.StringType, stateRoleTags)
		state.Roles = append(state.Roles, stateRole)
	}

	setStateDiags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
}
