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
	_ datasource.DataSource              = &iamUsersDataSource{}
	_ datasource.DataSourceWithConfigure = &iamUsersDataSource{}
)

func NewIamUsersDataSource() datasource.DataSource {
	return &iamUsersDataSource{}
}

type iamUsersDataSource struct {
	client *awsIAMClient.Client
}

type iamUsersDataSourceModel struct {
	Tags  types.Map        `tfsdk:"tags"`
	Users []*iamUserDetail `tfsdk:"users"`
}

type iamUserDetail struct {
	Arn              types.String `tfsdk:"arn"`
	CreateDate       types.String `tfsdk:"create_date"`
	Path             types.String `tfsdk:"path"`
	UserId           types.String `tfsdk:"user_id"`
	UserName         types.String `tfsdk:"user_name"`
	PasswordLastUsed types.String `tfsdk:"password_last_used"`
	Tags             types.Map    `tfsdk:"tags"`
}

func (d *iamUsersDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_iam_users"
}

func (d *iamUsersDataSource) Schema(_ context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve list of IAM users with attached tags.",
		Attributes: map[string]schema.Attribute{
			"tags": schema.MapAttribute{
				Description: "Filter by map of tags assigned to the IAM user.",
				ElementType: types.StringType,
				Optional:    true,
			},
			"users": schema.ListNestedAttribute{
				Description: "List of IAM users.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"arn": schema.StringAttribute{
							Description: "The Amazon Resource Name (ARN) that identifies the user.",
							Computed:    true,
						},
						"create_date": schema.StringAttribute{
							Description: "The date and time, in ISO 8601 date-time string format, when the user was created",
							Computed:    true,
						},
						"path": schema.StringAttribute{
							Description: "The path to the user.",
							Computed:    true,
						},
						"user_id": schema.StringAttribute{
							Description: "The stable and unique string identifying the user.",
							Computed:    true,
						},
						"user_name": schema.StringAttribute{
							Description: "The friendly name identifying the user.",
							Computed:    true,
						},
						"password_last_used": schema.StringAttribute{
							Description: "The date and time, in ISO 8601 date-time string format, when the user's password was last used to sign in to an Amazon Web Services website.",
							Computed:    true,
						},
						"tags": schema.MapAttribute{
							Description: "A list of tags that are associated with the user.",
							ElementType: types.StringType,
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

func (r *iamUsersDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, _ *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(awsClients).iamClient
}

func (d *iamUsersDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var plan *iamUsersDataSourceModel
	getPlanDiags := req.Config.Get(ctx, &plan)
	resp.Diagnostics.Append(getPlanDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
	state := &iamUsersDataSourceModel{}
	state.Users = []*iamUserDetail{}

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

	var iamUsersList []awsTypes.User
	listUsersFunc := func() error {
		// Init variable iamUsersList to solve redundant values in backoff retry.
		iamUsersList = []awsTypes.User{}
		listUsersInput := &awsIAMClient.ListUsersInput{}
		for {
			iamUsers, err := d.client.ListUsers(ctx, listUsersInput)
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
			iamUsersList = append(iamUsersList, iamUsers.Users...)
			if !iamUsers.IsTruncated {
				break
			}
			listUsersInput.Marker = iamUsers.Marker
		}
		return nil
	}

	listUsersBackoff := backoff.NewExponentialBackOff()
	listUsersBackoff.MaxElapsedTime = 1 * time.Minute
	err := backoff.Retry(listUsersFunc, listUsersBackoff)
	if err != nil {
		resp.Diagnostics.AddError(
			"[API ERROR] Failed to List IAM Users",
			err.Error(),
		)
		return
	}

iamUsersLoop:
	for _, iamUser := range iamUsersList {
		var iamUserTagsList []awsTypes.Tag
		listUserTagsFunc := func() error {
			// Init variable iamUserTagsList to solve redundant values in backoff retry.
			iamUserTagsList = []awsTypes.Tag{}
			listUserTagsInput := &awsIAMClient.ListUserTagsInput{
				UserName: iamUser.UserName,
			}
			for {
				iamUserTags, err := d.client.ListUserTags(ctx, listUserTagsInput)
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
				iamUserTagsList = append(iamUserTagsList, iamUserTags.Tags...)
				if !iamUserTags.IsTruncated {
					break
				}
				listUserTagsInput.Marker = iamUserTags.Marker
			}
			return nil
		}

		listUserTagsBackoff := backoff.NewExponentialBackOff()
		listUserTagsBackoff.MaxElapsedTime = 1 * time.Minute
		err := backoff.Retry(listUserTagsFunc, listUserTagsBackoff)
		if err != nil {
			resp.Diagnostics.AddError(
				"[API ERROR] Failed to List IAM User's Tags",
				err.Error(),
			)
			return
		}

	matchUserTagsLoop:
		for key, value := range inputTags {
			for _, iamUserTag := range iamUserTagsList {
				if *iamUserTag.Key == key && *iamUserTag.Value == value {
					// When the tag is found, continue to next tag.
					continue matchUserTagsLoop
				}
			}
			// When a pair of tag is not matched, continue to next user.
			continue iamUsersLoop
		}

		stateUser := &iamUserDetail{
			Arn:        types.StringValue(*iamUser.Arn),
			CreateDate: types.StringValue(iamUser.CreateDate.String()),
			Path:       types.StringValue(*iamUser.Path),
			UserId:     types.StringValue(*iamUser.UserId),
			UserName:   types.StringValue(*iamUser.UserName),
		}
		if iamUser.PasswordLastUsed != nil {
			stateUser.PasswordLastUsed = types.StringValue(iamUser.PasswordLastUsed.String())
		}
		stateUserTags := make(map[string]attr.Value)
		for _, iamUserTag := range iamUserTagsList {
			stateUserTags[*iamUserTag.Key] = types.StringValue(*iamUserTag.Value)
		}
		stateUser.Tags = types.MapValueMust(types.StringType, stateUserTags)
		state.Users = append(state.Users, stateUser)
	}

	setStateDiags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
}
