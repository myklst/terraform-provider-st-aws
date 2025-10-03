package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsIamClient "github.com/aws/aws-sdk-go-v2/service/iam"
	awsSsoAdminClient "github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	ssoTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/smithy-go"
	"github.com/cenkalti/backoff"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const (
	// Number of 30 indicates the character length of neccessary policy keyword
	// such as "Version" and "Statement" and some JSON symbols ({}, []).
	policyV2KeywordLength = 30
	policyV2MaxLength     = 6144
)

var (
	_ resource.Resource              = &iamPolicyV2Resource{}
	_ resource.ResourceWithConfigure = &iamPolicyV2Resource{}
)

func NewIamPolicyV2Resource() resource.Resource {
	return &iamPolicyV2Resource{}
}

type iamPolicyV2Resource struct {
	client *awsIamClient.Client
	sso    *awsSsoAdminClient.Client
}

type iamPolicyV2ResourceModel struct {
	Role                   *roleBlock          `tfsdk:"role"`
	User                   *userBlock          `tfsdk:"user"`
	PermissionSet          *permissionSetBlock `tfsdk:"permission_set"`
	AttachedPolicies       types.List          `tfsdk:"attached_policies"`
	AttachedPoliciesDetail []*policyV2Detail   `tfsdk:"attached_policies_detail"`
	CombinedPolicesDetail  []*policyV2Detail   `tfsdk:"combined_policies_detail"`
}

type roleBlock struct {
	RoleName types.String `tfsdk:"role_name"`
}

type userBlock struct {
	UserName types.String `tfsdk:"user_name"`
}

type permissionSetBlock struct {
	PolicyName       types.String `tfsdk:"policy_name"`
	InstanceArn      types.String `tfsdk:"instance_arn"`
	PermissionSetArn types.String `tfsdk:"permission_set_arn"`
	PolicyPath       types.String `tfsdk:"policy_path"`
}

type policyV2Detail struct {
	PolicyName     types.String `tfsdk:"policy_name"`
	PolicyDocument types.String `tfsdk:"policy_document"`
}

func (r *iamPolicyV2Resource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_iam_policy_v2"
}

func (r *iamPolicyV2Resource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provides an IAM Policy resource that manages policy content " +
			"exceeding character limits by splitting it into smaller segments. " +
			"These segments are combined to form a complete policy and attached to the chosen target. " +
			"Policies like `ReadOnlyAccess` that exceed the maximum length are attached directly.",
		Attributes: map[string]schema.Attribute{
			"attached_policies": schema.ListAttribute{
				Description: "List of IAM policy.",
				ElementType: types.StringType,
				Required:    true,
			},
			"attached_policies_detail": schema.ListNestedAttribute{
				Description: "A list of policies detail.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"policy_name": schema.StringAttribute{
							Description: "The policy name.",
							Computed:    true,
						},
						"policy_document": schema.StringAttribute{
							Description: "The policy document of the IAM policy.",
							Computed:    true,
						},
					},
				},
			},
			"combined_policies_detail": schema.ListNestedAttribute{
				Description: "A list of combined policies that are attached to targets.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"policy_name": schema.StringAttribute{
							Description: "The policy name.",
							Computed:    true,
						},
						"policy_document": schema.StringAttribute{
							Description: "The policy document of the IAM policy.",
							Computed:    true,
						},
					},
				},
			},
		},
		Blocks: map[string]schema.Block{
			"role": schema.SingleNestedBlock{
				Description: "Attach to an IAM Role.",
				Attributes: map[string]schema.Attribute{
					"role_name": schema.StringAttribute{
						Description: "Target IAM Role name.",
						Optional:    true,
					},
				},
			},
			"user": schema.SingleNestedBlock{
				Description: "Attach to an IAM User.",
				Attributes: map[string]schema.Attribute{
					"user_name": schema.StringAttribute{
						Description: "Target IAM User name.",
						Optional:    true,
					},
				},
			},
			"permission_set": schema.SingleNestedBlock{
				Description: "Attach to an Identity Center Permission Set.",
				Attributes: map[string]schema.Attribute{
					"policy_name": schema.StringAttribute{
						Description: "Logical name for the combined policy attached to the Permission Set.",
						Optional:    true,
					},
					"instance_arn": schema.StringAttribute{
						Description: "Identity Center Instance ARN.",
						Optional:    true,
					},
					"permission_set_arn": schema.StringAttribute{
						Description: "Target Permission Set ARN.",
						Optional:    true,
					},
					"policy_path": schema.StringAttribute{
						Description: "Policy path for customer-managed policy references.",
						Optional:    true,
						Computed:    true,
					},
				},
			},
		},
	}
}

func (r *iamPolicyV2Resource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(awsClients).iamClient
	r.sso = req.ProviderData.(awsClients).ssoAdminClient
}

func (r *iamPolicyV2Resource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan *iamPolicyV2ResourceModel
	if diags := req.Config.Get(ctx, &plan); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	// The configuration must contain exactly one role block, one user block, and one permission_set block.
	targetCount := 0
	if plan.Role != nil {
		targetCount++
	}
	if plan.User != nil {
		targetCount++
	}
	if plan.PermissionSet != nil {
		targetCount++
	}
	if targetCount == 0 {
		resp.Diagnostics.AddError("Missing target block", "One of `role {}`, `user {}`, or `permission_set {}` must be provided.")
		return
	}
	if targetCount > 1 {
		resp.Diagnostics.AddError("Conflicting target blocks", "Only one of `role {}`, `user {}`, or `permission_set {}` can be set at a time.")
		return
	}

	// Check if PermissionSet block is config. Set default path "/", require instance_arn & permission_set_arn, and ensure the SSO client is initialized.
	// createPolicy and all switch-case paths depend on a normalized PermissionSet and an initialized SSO client.
	if plan.PermissionSet != nil {
		if plan.PermissionSet.PolicyPath.IsNull() || plan.PermissionSet.PolicyPath.IsUnknown() || plan.PermissionSet.PolicyPath.ValueString() == "" {
			plan.PermissionSet.PolicyPath = types.StringValue("/") // The default policy path is "/".
		}
		if plan.PermissionSet.InstanceArn.IsUnknown() || plan.PermissionSet.InstanceArn.IsNull() ||
			plan.PermissionSet.PermissionSetArn.IsUnknown() || plan.PermissionSet.PermissionSetArn.IsNull() {
			resp.Diagnostics.AddError("Missing required Identity Center fields", "`permission_set.instance_arn` and `permission_set.permission_set_arn` are required.")
			return
		}
		if r.sso == nil {
			resp.Diagnostics.AddError("SSO Admin client not initialized", "The SSO Admin client is nil. Ensure the provider constructs ssoadmin.Client and sets it in ProviderData.")
			return
		}
	}

	combined, attached, createErrs := r.createPolicy(ctx, plan)
	addDiagnostics(&resp.Diagnostics, "error", "[API ERROR] Failed to Create the Policy.", createErrs, "")
	if resp.Diagnostics.HasError() {
		return
	}

	state := &iamPolicyV2ResourceModel{
		AttachedPolicies:       plan.AttachedPolicies,
		AttachedPoliciesDetail: attached,
		CombinedPolicesDetail:  combined,
		Role:                   plan.Role,
		User:                   plan.User,
		PermissionSet:          plan.PermissionSet,
	}

	switch {
	case plan.Role != nil:
		if errs := r.attachPolicyToRole(ctx, state); len(errs) > 0 {
			addDiagnostics(&resp.Diagnostics, "error", "[API ERROR] Failed to Attach Policy to Role.", errs, "")
			return
		}
		nf, re := r.readCombinedPolicy(ctx, state)
		addDiagnostics(&resp.Diagnostics, "error",
			fmt.Sprintf("[API ERROR] Failed to Read Combined Policies for %v: Policy Not Found!", plan.Role.RoleName),
			nf, "")
		addDiagnostics(&resp.Diagnostics, "error",
			fmt.Sprintf("[API ERROR] Failed to Read Combined Policies for %v: Unexpected Error!", plan.Role.RoleName),
			re, "")
		if resp.Diagnostics.HasError() {
			return
		}

	case plan.User != nil:
		if errs := r.attachPolicyToUser(ctx, state); len(errs) > 0 {
			addDiagnostics(&resp.Diagnostics, "error", "[API ERROR] Failed to Attach Policy to User.", errs, "")
			return
		}
		nf, re := r.readCombinedPolicy(ctx, state)
		addDiagnostics(&resp.Diagnostics, "error",
			fmt.Sprintf("[API ERROR] Failed to Read Combined Policies for %v: Policy Not Found!", plan.User.UserName),
			nf, "")
		addDiagnostics(&resp.Diagnostics, "error",
			fmt.Sprintf("[API ERROR] Failed to Read Combined Policies for %v: Unexpected Error!", plan.User.UserName),
			re, "")
		if resp.Diagnostics.HasError() {
			return
		}

	case plan.PermissionSet != nil:
		var createdCombined []*policyV2Detail
		var excludedOriginals []*policyV2Detail
		prefix := plan.PermissionSet.PolicyName.ValueString() + "-"
		for _, d := range combined {
			if strings.HasPrefix(d.PolicyName.ValueString(), prefix) {
				createdCombined = append(createdCombined, d)
			} else {
				excludedOriginals = append(excludedOriginals, d)
			}
		}

		var awsManagedArns []string
		var excludedCustomerManaged []*policyV2Detail
		var bucketErrs []error

		isAWSManaged := func(s string) bool {
			a, err := arn.Parse(s)
			return err == nil && a.Service == "iam" && a.AccountID == "aws"
		}
		for _, e := range excludedOriginals {
			arnStr, _, err := r.getPolicyArn(ctx, e.PolicyName.ValueString())
			if err != nil {
				bucketErrs = append(bucketErrs, err)
				continue
			}
			if arnStr == "" {
				bucketErrs = append(bucketErrs, fmt.Errorf("policy %q not found while bucketing", e.PolicyName.ValueString()))
				continue
			}
			if isAWSManaged(arnStr) {
				awsManagedArns = append(awsManagedArns, arnStr)
			} else {
				excludedCustomerManaged = append(excludedCustomerManaged, e)
			}
		}
		addDiagnostics(&resp.Diagnostics, "error", "[API ERROR] Failed to resolve excluded policy ownership.", bucketErrs, "")
		if resp.Diagnostics.HasError() {
			return
		}

		state.CombinedPolicesDetail = append(createdCombined, excludedCustomerManaged...)

		nf, re := r.readCombinedPolicy(ctx, state)
		addDiagnostics(&resp.Diagnostics, "error",
			fmt.Sprintf("[API ERROR] Failed to Read Combined Policies for %v: Policy Not Found!", state.PermissionSet.PolicyName),
			nf, "")
		addDiagnostics(&resp.Diagnostics, "error",
			fmt.Sprintf("[API ERROR] Failed to Read Combined Policies for %v: Unexpected Error!", state.PermissionSet.PolicyName),
			re, "")
		if resp.Diagnostics.HasError() {
			return
		}

		if errs := r.attachCustomerPoliciesToPermissionSet(ctx, state); len(errs) > 0 {
			addDiagnostics(&resp.Diagnostics, "error",
				"[API ERROR] Failed to attach customer-managed policies to Permission Set.",
				errs, "")
			return
		}

		if len(awsManagedArns) > 0 {
			if mpErrs := r.attachAWSManagedPoliciesToPermissionSet(ctx, state, awsManagedArns); len(mpErrs) > 0 {
				addDiagnostics(&resp.Diagnostics, "error",
					"[API ERROR] Failed to attach AWS-managed policies to Permission Set.",
					mpErrs, "")
				return
			}
		}

		if provErrs := r.provisionPermissionSetAll(ctx, state); len(provErrs) > 0 {
			addDiagnostics(&resp.Diagnostics, "error", "[API ERROR] Failed to provision Permission Set.", provErrs, "")
			return
		}
	}

	if diags := resp.State.Set(ctx, &state); diags.HasError() {
		resp.Diagnostics.Append(diags...)
	}
}

func (r *iamPolicyV2Resource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state *iamPolicyV2ResourceModel
	if diags := req.State.Get(ctx, &state); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	if state.PermissionSet != nil {
		if state.PermissionSet.PolicyPath.IsNull() || state.PermissionSet.PolicyPath.IsUnknown() || state.PermissionSet.PolicyPath.ValueString() == "" {
			state.PermissionSet.PolicyPath = types.StringValue("/")
		}
	}

	var oriState *iamPolicyV2ResourceModel
	if diags := req.State.Get(ctx, &oriState); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	if oriState.PermissionSet != nil {
		if oriState.PermissionSet.PolicyPath.IsNull() || oriState.PermissionSet.PolicyPath.IsUnknown() || oriState.PermissionSet.PolicyPath.ValueString() == "" {
			oriState.PermissionSet.PolicyPath = types.StringValue("/")
		}
	}

	subject := func() string {
		switch {
		case state.Role != nil:
			return state.Role.RoleName.ValueString()
		case state.User != nil:
			return state.User.UserName.ValueString()
		case state.PermissionSet != nil:
			return state.PermissionSet.PolicyName.ValueString()
		default:
			return "(unknown-target)"
		}
	}()

	nfCombined, errCombined := r.readCombinedPolicy(ctx, state)
	addDiagnostics(&resp.Diagnostics, "warning",
		fmt.Sprintf("[API WARNING] Failed to Read Combined Policies for %v: Policy Not Found!", subject),
		nfCombined, "The combined policies may be deleted due to human mistake or API error, will trigger update to recreate the combined policy:",
	)
	addDiagnostics(&resp.Diagnostics, "error",
		fmt.Sprintf("[API ERROR] Failed to Read Combined Policies for %v: Unexpected Error!", subject),
		errCombined, "",
	)
	if diags := resp.State.Set(ctx, &state); diags.HasError() {
		resp.Diagnostics.Append(diags...)
	}
	if resp.Diagnostics.WarningsCount() > 0 || resp.Diagnostics.HasError() {
		return
	}

	nfAttached, errAttached := r.readAttachedPolicy(ctx, state)
	addDiagnostics(&resp.Diagnostics, "warning",
		fmt.Sprintf("[API WARNING] Failed to Read Attached Policies for %v: Policy Not Found!", subject),
		nfAttached, "The policy that will be used to combine policies had been removed on AWS, next apply with update will prompt error:",
	)
	addDiagnostics(&resp.Diagnostics, "error",
		fmt.Sprintf("[API ERROR] Failed to Read Attached Policies for %v: Unexpected Error!", subject),
		errAttached, "",
	)
	if diags := resp.State.Set(ctx, &state); diags.HasError() {
		resp.Diagnostics.Append(diags...)
	}
	if resp.Diagnostics.WarningsCount() > 0 || resp.Diagnostics.HasError() {
		return
	}

	driftErr := r.checkPoliciesDrift(state, oriState)
	addDiagnostics(&resp.Diagnostics, "warning",
		fmt.Sprintf("[API WARNING] Policy Drift Detected for %v.", subject),
		[]error{driftErr}, "This resource will be updated in the next terraform apply.",
	)

	if diags := resp.State.Set(ctx, &state); diags.HasError() {
		resp.Diagnostics.Append(diags...)
	}
}

func (r *iamPolicyV2Resource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state *iamPolicyV2ResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	subjectsSet := 0
	if plan.Role != nil {
		subjectsSet++
	}
	if plan.User != nil {
		subjectsSet++
	}
	if plan.PermissionSet != nil {
		subjectsSet++
	}

	if subjectsSet != 1 {
		resp.Diagnostics.AddError(
			"Invalid target selection",
			"Exactly one of `role`, `user`, or `permission_set` must be specified.",
		)
		return
	}

	isRole := plan.Role != nil && !plan.Role.RoleName.IsNull() && !plan.Role.RoleName.IsUnknown() && plan.Role.RoleName.ValueString() != ""
	isUser := plan.User != nil && !plan.User.UserName.IsNull() && !plan.User.UserName.IsUnknown() && plan.User.UserName.ValueString() != ""
	isPS := plan.PermissionSet != nil &&
		!plan.PermissionSet.InstanceArn.IsNull() && !plan.PermissionSet.InstanceArn.IsUnknown() &&
		!plan.PermissionSet.PermissionSetArn.IsNull() && !plan.PermissionSet.PermissionSetArn.IsUnknown()

	if isPS {
		if plan.PermissionSet.PolicyPath.IsNull() || plan.PermissionSet.PolicyPath.IsUnknown() || plan.PermissionSet.PolicyPath.ValueString() == "" {
			plan.PermissionSet.PolicyPath = types.StringValue("/")
		}
		if r.sso == nil {
			resp.Diagnostics.AddError(
				"SSO Admin client not initialized",
				"The SSO Admin client is nil. Ensure the provider constructs ssoadmin.Client and sets it in ProviderData.",
			)
			return
		}
	}

	readAttachedPolicyNotExistErr, readAttachedPolicyErr := r.readAttachedPolicy(ctx, plan)
	switch {
	case isRole:
		addDiagnostics(&resp.Diagnostics, "error",
			fmt.Sprintf("[API ERROR] Failed to Read Attached Policies for %v: Policy Not Found!", state.Role.RoleName),
			readAttachedPolicyNotExistErr, "The policy that will be used to combine policies had been removed on AWS:")
		addDiagnostics(&resp.Diagnostics, "error",
			fmt.Sprintf("[API ERROR] Failed to Read Attached Policies for %v: Unexpected Error!", state.Role.RoleName),
			readAttachedPolicyErr, "")
	case isUser:
		addDiagnostics(&resp.Diagnostics, "error",
			fmt.Sprintf("[API ERROR] Failed to Read Attached Policies for %v: Policy Not Found!", state.User.UserName),
			readAttachedPolicyNotExistErr, "The policy that will be used to combine policies had been removed on AWS:")
		addDiagnostics(&resp.Diagnostics, "error",
			fmt.Sprintf("[API ERROR] Failed to Read Attached Policies for %v: Unexpected Error!", state.User.UserName),
			readAttachedPolicyErr, "")
	case isPS:
		addDiagnostics(&resp.Diagnostics, "error",
			fmt.Sprintf("[API ERROR] Failed to Read Attached Policies for %v: Policy Not Found!", state.PermissionSet.PolicyName),
			readAttachedPolicyNotExistErr, "The policy that will be used to combine policies had been removed on AWS:")
		addDiagnostics(&resp.Diagnostics, "error",
			fmt.Sprintf("[API ERROR] Failed to Read Attached Policies for %v: Unexpected Error!", state.PermissionSet.PolicyName),
			readAttachedPolicyErr, "")
	}
	if resp.Diagnostics.HasError() {
		return
	}

	if isPS {
		detachErrs := r.detachCustomerPoliciesFromPermissionSet(ctx, state)
		addDiagnostics(&resp.Diagnostics, "error",
			"[API ERROR] Failed to detach customer-managed policies from Permission Set.",
			detachErrs, "")
		if resp.Diagnostics.HasError() {
			return
		}

		preProvErrs := r.provisionPermissionSetAll(ctx, state)
		addDiagnostics(&resp.Diagnostics, "error",
			"[API ERROR] Failed to provision Permission Set after detach.",
			preProvErrs, "")
		if resp.Diagnostics.HasError() {
			return
		}
	}

	removePolicyErr := r.removePolicy(ctx, state)
	switch {
	case isRole:
		addDiagnostics(&resp.Diagnostics, "error",
			fmt.Sprintf("[API ERROR] Failed to Remove Policies for %v: Unexpected Error!", state.Role.RoleName),
			removePolicyErr, "")
	case isUser:
		addDiagnostics(&resp.Diagnostics, "error",
			fmt.Sprintf("[API ERROR] Failed to Remove Policies for %v: Unexpected Error!", state.User.UserName),
			removePolicyErr, "")
	case isPS:
		addDiagnostics(&resp.Diagnostics, "error",
			fmt.Sprintf("[API ERROR] Failed to Remove Policies for %v: Unexpected Error!", state.PermissionSet.PolicyName),
			removePolicyErr, "")
	}
	if resp.Diagnostics.HasError() {
		return
	}

	state.CombinedPolicesDetail = nil
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	combinedPolicies, attachedPolicies, createErrs := r.createPolicy(ctx, plan)
	addDiagnostics(&resp.Diagnostics, "error",
		"[API ERROR] Failed to Create the Policy.",
		createErrs, "")
	if resp.Diagnostics.HasError() {
		return
	}

	state.AttachedPolicies = plan.AttachedPolicies
	state.AttachedPoliciesDetail = attachedPolicies
	state.CombinedPolicesDetail = combinedPolicies

	if isRole {
		if state.Role == nil {
			state.Role = &roleBlock{}
		}
		state.Role.RoleName = plan.Role.RoleName
	}
	if isUser {
		if state.User == nil {
			state.User = &userBlock{}
		}
		state.User.UserName = plan.User.UserName
	}
	if isPS {
		if state.PermissionSet == nil {
			state.PermissionSet = &permissionSetBlock{}
		}
		state.PermissionSet.PolicyName = plan.PermissionSet.PolicyName
		state.PermissionSet.PolicyPath = plan.PermissionSet.PolicyPath
		state.PermissionSet.InstanceArn = plan.PermissionSet.InstanceArn
		state.PermissionSet.PermissionSetArn = plan.PermissionSet.PermissionSetArn
	}

	readCombinedPolicyNotExistErr, readCombinedPolicyErr := r.readCombinedPolicy(ctx, state)
	switch {
	case isRole:
		addDiagnostics(&resp.Diagnostics, "error",
			fmt.Sprintf("[API ERROR] Failed to Read Combined Policies for %v: Policy Not Found!", state.Role.RoleName),
			readCombinedPolicyNotExistErr, "")
		addDiagnostics(&resp.Diagnostics, "error",
			fmt.Sprintf("[API ERROR] Failed to Read Combined Policies for %v: Unexpected Error!", state.Role.RoleName),
			readCombinedPolicyErr, "")
	case isUser:
		addDiagnostics(&resp.Diagnostics, "error",
			fmt.Sprintf("[API ERROR] Failed to Read Combined Policies for %v: Policy Not Found!", state.User.UserName),
			readCombinedPolicyNotExistErr, "")
		addDiagnostics(&resp.Diagnostics, "error",
			fmt.Sprintf("[API ERROR] Failed to Read Combined Policies for %v: Unexpected Error!", state.User.UserName),
			readCombinedPolicyErr, "")
	case isPS:
		addDiagnostics(&resp.Diagnostics, "error",
			fmt.Sprintf("[API ERROR] Failed to Read Combined Policies for %v: Policy Not Found!", state.PermissionSet.PolicyName),
			readCombinedPolicyNotExistErr, "")
		addDiagnostics(&resp.Diagnostics, "error",
			fmt.Sprintf("[API ERROR] Failed to Read Combined Policies for %v: Unexpected Error!", state.PermissionSet.PolicyName),
			readCombinedPolicyErr, "")
	}
	if resp.Diagnostics.HasError() {
		return
	}

	if isRole {
		errs := r.attachPolicyToRole(ctx, state)
		addDiagnostics(&resp.Diagnostics, "error", "[API ERROR] Failed to Attach Policy to Role.", errs, "")
		if resp.Diagnostics.HasError() {
			return
		}
	} else if isUser {
		errs := r.attachPolicyToUser(ctx, state)
		addDiagnostics(&resp.Diagnostics, "error", "[API ERROR] Failed to Attach Policy to User.", errs, "")
		if resp.Diagnostics.HasError() {
			return
		}
	} else if isPS {
		attachErrs := r.attachCustomerPoliciesToPermissionSet(ctx, state)
		addDiagnostics(&resp.Diagnostics, "error",
			"[API ERROR] Failed to attach customer-managed policies to Permission Set.",
			attachErrs, "")
		if resp.Diagnostics.HasError() {
			return
		}

		postProvErrs := r.provisionPermissionSetAll(ctx, state)
		addDiagnostics(&resp.Diagnostics, "error",
			"[API ERROR] Failed to provision Permission Set after attach.",
			postProvErrs, "")
		if resp.Diagnostics.HasError() {
			return
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *iamPolicyV2Resource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state *iamPolicyV2ResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if state.PermissionSet != nil {
		if state.PermissionSet.PolicyPath.IsNull() || state.PermissionSet.PolicyPath.IsUnknown() || state.PermissionSet.PolicyPath.ValueString() == "" {
			state.PermissionSet.PolicyPath = types.StringValue("/")
		}
	}

	subject := func() string {
		switch {
		case state.Role != nil:
			return state.Role.RoleName.ValueString()
		case state.User != nil:
			return state.User.UserName.ValueString()
		case state.PermissionSet != nil:
			return state.PermissionSet.PolicyName.ValueString()
		default:
			return "(unknown-target)"
		}
	}()

	switch {
	case state.PermissionSet != nil:
		if r.sso != nil &&
			!state.PermissionSet.InstanceArn.IsNull() && !state.PermissionSet.InstanceArn.IsUnknown() &&
			!state.PermissionSet.PermissionSetArn.IsNull() && !state.PermissionSet.PermissionSetArn.IsUnknown() {

			// Detach customer-managed from permission set.
			detachErrs := r.detachCustomerPoliciesFromPermissionSet(ctx, state)
			addDiagnostics(&resp.Diagnostics, "error",
				"[API ERROR] Failed to detach customer-managed policies from Permission Set.",
				detachErrs, "")
			if resp.Diagnostics.HasError() {
				return
			}

			// Provision after detach.
			provErrs := r.provisionPermissionSetAll(ctx, state)
			addDiagnostics(&resp.Diagnostics, "error",
				"[API ERROR] Failed to provision Permission Set after detach.", provErrs, "")
			if resp.Diagnostics.HasError() {
				return
			}
		}

		// Remove the combined customer-managed policies.
		rmErrs := r.removePolicy(ctx, state)
		addDiagnostics(&resp.Diagnostics, "error",
			fmt.Sprintf("[API ERROR] Failed to Remove Policies for %v: Unexpected Error!", subject),
			rmErrs, "")
		return

	case state.Role != nil:
		rmErrs := r.removePolicy(ctx, state)
		addDiagnostics(&resp.Diagnostics, "error",
			fmt.Sprintf("[API ERROR] Failed to Remove Policies for %v: Unexpected Error!", subject),
			rmErrs, "")
		if resp.Diagnostics.HasError() {
			return
		}
		return

	case state.User != nil:
		rmErrs := r.removePolicy(ctx, state)
		addDiagnostics(&resp.Diagnostics, "error",
			fmt.Sprintf("[API ERROR] Failed to Remove Policies for %v: Unexpected Error!", subject),
			rmErrs, "")
		if resp.Diagnostics.HasError() {
			return
		}
		return
	}

	resp.Diagnostics.AddError("Missing target block", "One of `role {}`, `user {}`, or `permission_set {}` must be provided.")
}

// `createPolicy` creates customer-managed IAM policies from the combined JSON documents.
//
// Parameters:
//   - ctx : Request context.
//   - plan: Desired configuration (role/user/permission_set, attached policies, etc.).
//
// Returns:
//   - combinedPoliciesDetail  : Details of policies created from combined docs plus any excluded originals.
//   - attachedPoliciesDetail  : Details describing the original inputs used (from combinePolicyDocument), for drift checks.
//   - errList                 : Non-nil on failure (e.g., API errors during creation); nil on success.
func (r *iamPolicyV2Resource) createPolicy(ctx context.Context, plan *iamPolicyV2ResourceModel) (combinedPoliciesDetail []*policyV2Detail, attachedPoliciesDetail []*policyV2Detail, errList []error) {
	var policies []string
	plan.AttachedPolicies.ElementsAs(ctx, &policies, false)

	combinedDocs, excludedPolicies, attachedPoliciesDetail, errList := r.combinePolicyDocument(ctx, plan)
	if errList != nil {
		return nil, nil, errList
	}

	var (
		prefix  string
		pathPtr *string
		usePath bool
	)
	switch {
	case plan.Role != nil:
		prefix = plan.Role.RoleName.ValueString()
	case plan.User != nil:
		prefix = plan.User.UserName.ValueString()
	case plan.PermissionSet != nil:
		prefix = plan.PermissionSet.PolicyName.ValueString()
		// If want to create policies under a specific path for permission sets.
		if !plan.PermissionSet.PolicyPath.IsNull() && !plan.PermissionSet.PolicyPath.IsUnknown() && plan.PermissionSet.PolicyPath.ValueString() != "" {
			path := plan.PermissionSet.PolicyPath.ValueString()
			pathPtr = &path
			usePath = true
		}
	default:
		return nil, nil, []error{fmt.Errorf("no target block (role/user/permission_set) was set")}
	}

	create := func() error {
		for i, doc := range combinedDocs {
			policyName := fmt.Sprintf("%s-%d", prefix, i+1)

			in := &awsIamClient.CreatePolicyInput{
				PolicyName:     aws.String(policyName),
				PolicyDocument: aws.String(doc),
			}
			if usePath {
				in.Path = pathPtr
			}

			if _, err := r.client.CreatePolicy(ctx, in); err != nil {
				return handleAPIError(err)
			}
		}
		return nil
	}

	back := backoff.NewExponentialBackOff()
	back.MaxElapsedTime = 30 * time.Second
	if err := backoff.Retry(create, back); err != nil {
		return nil, nil, []error{err}
	}

	for i, doc := range combinedDocs {
		policyName := fmt.Sprintf("%s-%d", prefix, i+1)
		combinedPoliciesDetail = append(combinedPoliciesDetail, &policyV2Detail{
			PolicyName:     types.StringValue(policyName),
			PolicyDocument: types.StringValue(doc),
		})
	}

	combinedPoliciesDetail = append(combinedPoliciesDetail, excludedPolicies...)
	return combinedPoliciesDetail, attachedPoliciesDetail, nil
}

// `combinePolicyDocument` packs multiple IAM policy documents into size-bounded “combined” policies.
//
// Parameters:
//   - ctx  : Request context.
//   - plan : Desired configuration containing the attached policy IDs.
//
// Returns:
//   - combinedPolicyDocument : JSON strings of the newly combined policy documents (each under size limits).
//   - excludedPolicies       : Policies that individually exceed the limit and must be attached as-is.
//   - attachedPoliciesDetail : Details of all fetched inputs (used for drift detection/diagnostics).
//   - errList                : Non-nil if fetch/unmarshal/processing failed; nil on success.
func (r *iamPolicyV2Resource) combinePolicyDocument(ctx context.Context, plan *iamPolicyV2ResourceModel) (combinedPolicyDocument []string, excludedPolicies []*policyV2Detail, attachedPoliciesDetail []*policyV2Detail, errList []error) {
	var inputIDs []string
	plan.AttachedPolicies.ElementsAs(ctx, &inputIDs, false)

	attachedPoliciesDetail, notFound, unexpected := r.fetchPolicies(ctx, inputIDs)
	errList = append(errList, notFound...)
	errList = append(errList, unexpected...)
	if len(errList) != 0 {
		return nil, nil, nil, errList
	}

	maxLen := policyV2MaxLength
	keywordLen := policyV2KeywordLength

	currentLen := 0
	currentStmt := ""
	var stmtBuckets []string

	for _, ap := range attachedPoliciesDetail {
		raw, err := url.QueryUnescape(ap.PolicyDocument.ValueString())
		if err != nil {
			return nil, nil, nil, append(errList, err)
		}

		singlePolicy := strings.Join(strings.Fields(raw), "")
		if len(singlePolicy) > maxLen {
			excludedPolicies = append(excludedPolicies, &policyV2Detail{
				PolicyName:     ap.PolicyName,
				PolicyDocument: types.StringValue(raw),
			})
			continue
		}

		var doc map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &doc); err != nil {
			return nil, nil, nil, append(errList, err)
		}
		stmtBytes, err := json.Marshal(doc["Statement"])
		if err != nil {
			return nil, nil, nil, append(errList, err)
		}
		finalStmt := strings.Trim(string(stmtBytes), "[]")

		// Check if adding this would overflow the policy size.
		if (currentLen + len(finalStmt) + keywordLen) > maxLen {
			currentStmt = strings.TrimSuffix(currentStmt, ",")
			if currentStmt != "" {
				stmtBuckets = append(stmtBuckets, currentStmt)
			}
			currentStmt = finalStmt + ","
			currentLen = len(finalStmt)
		} else {
			currentStmt += finalStmt + ","
			currentLen += len(finalStmt)
		}
	}

	if len(currentStmt) > 0 {
		currentStmt = strings.TrimSuffix(currentStmt, ",")
		stmtBuckets = append(stmtBuckets, currentStmt)
	}

	for _, statement := range stmtBuckets {
		combinedPolicyDocument = append(
			combinedPolicyDocument,
			fmt.Sprintf(`{"Version":"2012-10-17","Statement":[%s]}`, statement),
		)
	}

	return combinedPolicyDocument, excludedPolicies, attachedPoliciesDetail, nil
}

// `readCombinedPolicy` refreshes details for the previously created “combined” policies.
//
// Parameters:
//   - ctx   : Request context.
//   - state : Pointer to current resource state to be updated in place.
//
// Returns:
//   - notExistErrs    : Allowed “not found” errors (useful for warnings / drift notices); nil if none.
//   - unexpectedErrs  : Non-recoverable API/processing errors; nil on success.
func (r *iamPolicyV2Resource) readCombinedPolicy(ctx context.Context, state *iamPolicyV2ResourceModel) (notExistErrs, unexpectedErrs []error) {
	var policiesName []string
	for _, policy := range state.CombinedPolicesDetail {
		policiesName = append(policiesName, policy.PolicyName.ValueString())
	}

	policyDetails, notExistErrs, unexpectedErrs := r.fetchPolicies(ctx, policiesName)
	if len(unexpectedErrs) > 0 {
		return nil, unexpectedErrs
	}

	// If the combined policies not found from AWS, that it might be deleted
	// from outside Terraform. Set the state to Unknown to trigger state changes
	// and Update() function.
	if len(notExistErrs) > 0 {
		// This is to ensure Update() is called.
		state.AttachedPolicies = types.ListNull(types.StringType)
	}

	state.CombinedPolicesDetail = policyDetails
	return notExistErrs, nil
}

// `readAttachedPolicy` will read the attached policy details.
//
// Parameters:
//   - state: The state configurations, it will directly update the value of the struct since it is a pointer.
//
// Returns:
//   - notExistError: List of allowed not exist errors to be used as warning messages instead, return nil if no errors.
//   - unexpectedError: List of unexpected errors to be used as normal error messages, return nil if no errors.
func (r *iamPolicyV2Resource) readAttachedPolicy(ctx context.Context, state *iamPolicyV2ResourceModel) (notExistErrs, unexpectedErrs []error) {
	var policiesName []string
	for _, policyName := range state.AttachedPolicies.Elements() {
		policiesName = append(policiesName, strings.Trim(policyName.String(), "\""))
	}

	policyDetails, notExistErrs, unexpectedErrs := r.fetchPolicies(ctx, policiesName)
	if len(unexpectedErrs) > 0 {
		return nil, unexpectedErrs
	}

	// If the combined policies not found from AWS, that it might be deleted
	// from outside Terraform. Set the state to Unknown to trigger state changes
	// and Update() function.
	if len(notExistErrs) > 0 {
		// This is to ensure Update() is called.
		state.AttachedPolicies = types.ListNull(types.StringType)
	}

	state.AttachedPoliciesDetail = policyDetails
	return notExistErrs, nil
}

// `fetchPolicies` looks up IAM policies by reference (name or ARN), then fetches their metadata and version docs.
//
// Parameters:
//   - ctx          : Request context.
//   - policiesName : Slice of policy references (friendly names or ARNs).
//
// Returns:
//   - policiesDetail : Details for all successfully fetched policies.
//   - notExistError  : Errors indicating a policy wasn’t found (safe to warn/continue).
//   - unexpectedError: Other API/processing errors (should usually surface as failures).
func (r *iamPolicyV2Resource) fetchPolicies(ctx context.Context, policiesName []string) (policiesDetail []*policyV2Detail, notExistError, unexpectedError []error) {
	var ae smithy.APIError

	for _, ref := range policiesName {
		policyArn, policyVersionID, err := r.getPolicyArn(ctx, ref)
		if err != nil {
			unexpectedError = append(unexpectedError, err)
			continue
		}
		if policyArn == "" && policyVersionID == "" {
			notExistError = append(notExistError, fmt.Errorf("policy %v does not exist", ref))
			continue
		}

		var verOut *awsIamClient.GetPolicyVersionOutput
		var polOut *awsIamClient.GetPolicyOutput

		getPolicy := func() error {
			verIn := &awsIamClient.GetPolicyVersionInput{
				PolicyArn: aws.String(policyArn),
				VersionId: aws.String(policyVersionID),
			}
			out1, err := r.client.GetPolicyVersion(ctx, verIn)
			if err != nil {
				return handleAPIError(err)
			}
			verOut = out1

			polIn := &awsIamClient.GetPolicyInput{PolicyArn: aws.String(policyArn)}
			out2, err := r.client.GetPolicy(ctx, polIn)
			if err != nil {
				return handleAPIError(err)
			}
			polOut = out2
			return nil
		}

		back := backoff.NewExponentialBackOff()
		back.MaxElapsedTime = 30 * time.Second
		err = backoff.Retry(getPolicy, back)

		if err != nil && errors.As(err, &ae) {
			switch ae.ErrorCode() {
			case "NoSuchEntity":
				notExistError = append(notExistError, err)
			default:
				unexpectedError = append(unexpectedError, err)
			}
			continue
		}
		policiesDetail = append(policiesDetail, &policyV2Detail{
			PolicyName:     types.StringValue(aws.ToString(polOut.Policy.PolicyName)),
			PolicyDocument: types.StringValue(aws.ToString(verOut.PolicyVersion.Document)),
		})
	}

	return policiesDetail, notExistError, unexpectedError
}

// `checkPoliciesDrift` compare the recorded AttachedPoliciesDetail documents with
// the latest IAM policy documents on AWS, and trigger Update() if policy
// drift is detected.
//
// Parameters:
//   - newState: New attached policy details that returned from AWS SDK.
//   - oriState: Original policy details that are recorded in Terraform state.
//
// Returns:
//   - error: The policy drifting error.
func (r *iamPolicyV2Resource) checkPoliciesDrift(newState, oriState *iamPolicyV2ResourceModel) error {
	var driftedPolicies []string

	for _, oldPolicyDetailState := range oriState.AttachedPoliciesDetail {
		for _, currPolicyDetailState := range newState.AttachedPoliciesDetail {
			if oldPolicyDetailState.PolicyName.String() == currPolicyDetailState.PolicyName.String() {
				if oldPolicyDetailState.PolicyDocument.String() != currPolicyDetailState.PolicyDocument.String() {
					driftedPolicies = append(driftedPolicies, oldPolicyDetailState.PolicyName.String())
				}
				break
			}
		}
	}

	if len(driftedPolicies) > 0 {
		// Set the state to trigger an update.
		newState.AttachedPolicies = types.ListNull(types.StringType)

		return fmt.Errorf(
			"the following policies documents had been changed since combining policies: [%s]",
			strings.Join(driftedPolicies, ", "),
		)
	}

	return nil
}

// `removePolicy` detaches and (when safe) deletes the previously created combined IAM policies.
//
// Parameters:
//   - ctx   : Request context.
//   - state : Current resource state (provides Role/User/PermissionSet and CombinedPolicesDetail).
//
// Returns:
//   - unexpectedError : Collected errors that should be surfaced as failures; nil on success.
func (r *iamPolicyV2Resource) removePolicy(ctx context.Context, state *iamPolicyV2ResourceModel) (unexpectedError []error) {
	var ae smithy.APIError

	permissionSetPath := "/"
	if state.PermissionSet != nil &&
		!state.PermissionSet.PolicyPath.IsNull() &&
		!state.PermissionSet.PolicyPath.IsUnknown() &&
		state.PermissionSet.PolicyPath.ValueString() != "" {
		permissionSetPath = state.PermissionSet.PolicyPath.ValueString()
	}

	remove := func() error {
		for _, combined := range state.CombinedPolicesDetail {
			var policyArn, versionID string
			arnBackoff := backoff.NewExponentialBackOff()
			arnBackoff.MaxElapsedTime = 30 * time.Second
			_ = backoff.Retry(func() error {
				var err error
				policyArn, versionID, err = r.getPolicyArn(ctx, combined.PolicyName.ValueString())
				if err != nil {
					return err
				}
				if len(policyArn) < 20 {
					return fmt.Errorf("policy ARN not yet available for %q (version=%s)", combined.PolicyName.ValueString(), versionID)
				}
				return nil
			}, arnBackoff)

			if len(policyArn) < 20 {
				continue
			}

			switch {
			case state.Role != nil:
				skipDelete := false

				if _, err := r.client.DetachRolePolicy(ctx, &awsIamClient.DetachRolePolicyInput{
					PolicyArn: aws.String(policyArn),
					RoleName:  aws.String(state.Role.RoleName.ValueString()),
				}); err != nil {
					if errors.As(err, &ae) {
						switch ae.ErrorCode() {
						case "NoSuchEntity":
						case "UnmodifiableEntity", "AccessDenied":
							skipDelete = true
						default:
							return handleAPIError(err)
						}
					} else {
						return handleAPIError(err)
					}
				}

				if !skipDelete {
					wait := backoff.NewExponentialBackOff()
					wait.MaxElapsedTime = 30 * time.Second
					if err := backoff.Retry(func() error {
						return r.ensurePolicyFullyDetached(ctx, policyArn)
					}, wait); err != nil {
						// Couldn’t prove detachment; don’t attempt deletion
						skipDelete = true
					}
				}

				if skipDelete {
					continue
				}

			case state.User != nil:
				if _, err := r.client.DetachUserPolicy(ctx, &awsIamClient.DetachUserPolicyInput{
					PolicyArn: aws.String(policyArn),
					UserName:  aws.String(state.User.UserName.ValueString()),
				}); err != nil && !(errors.As(err, &ae) && ae.ErrorCode() == "NoSuchEntity") {
					return handleAPIError(err)
				}

			case state.PermissionSet != nil:
				if r.sso != nil &&
					!state.PermissionSet.InstanceArn.IsNull() && !state.PermissionSet.InstanceArn.IsUnknown() &&
					!state.PermissionSet.PermissionSetArn.IsNull() && !state.PermissionSet.PermissionSetArn.IsUnknown() {
					arn, parseError := arn.Parse(policyArn)
					if parseError == nil && arn.Service == "iam" && arn.AccountID == "aws" {
						_, derr := r.sso.DetachManagedPolicyFromPermissionSet(ctx, &awsSsoAdminClient.DetachManagedPolicyFromPermissionSetInput{
							InstanceArn:      aws.String(state.PermissionSet.InstanceArn.ValueString()),
							PermissionSetArn: aws.String(state.PermissionSet.PermissionSetArn.ValueString()),
							ManagedPolicyArn: aws.String(policyArn),
						})
						if derr != nil && !(errors.As(derr, &ae) &&
							(ae.ErrorCode() == "ResourceNotFoundException" || ae.ErrorCode() == "ValidationException")) {
							return handleAPIError(derr)
						}
					} else {
						_, derr := r.sso.DetachCustomerManagedPolicyReferenceFromPermissionSet(ctx, &awsSsoAdminClient.DetachCustomerManagedPolicyReferenceFromPermissionSetInput{
							InstanceArn:      aws.String(state.PermissionSet.InstanceArn.ValueString()),
							PermissionSetArn: aws.String(state.PermissionSet.PermissionSetArn.ValueString()),
							CustomerManagedPolicyReference: &ssoTypes.CustomerManagedPolicyReference{
								Name: aws.String(combined.PolicyName.ValueString()),
								Path: aws.String(permissionSetPath),
							},
						})
						if derr != nil && !(errors.As(derr, &ae) &&
							(ae.ErrorCode() == "ResourceNotFoundException" || ae.ErrorCode() == "ValidationException")) {
							return handleAPIError(derr)
						}
					}
					_ = r.provisionPermissionSetAll(ctx, state)
				}
			}

			wait := backoff.NewExponentialBackOff()
			wait.MaxElapsedTime = 30 * time.Second
			if err := backoff.Retry(func() error {
				return r.ensurePolicyFullyDetached(ctx, policyArn)
			}, wait); err != nil {
				return err
			}

			arn, parseError := arn.Parse(policyArn)
			if parseError != nil || (arn.Service == "iam" && arn.AccountID == "aws") {
				continue
			}
			if arn.Service != "iam" || len(arn.AccountID) != 12 {
				continue
			}
			allDigits := true
			for _, ch := range arn.AccountID {
				if ch < '0' || ch > '9' {
					allDigits = false
					break
				}
			}
			if !allDigits {
				continue
			}

			policyVersion := awsIamClient.NewListPolicyVersionsPaginator(r.client, &awsIamClient.ListPolicyVersionsInput{
				PolicyArn: &policyArn,
			})
			for policyVersion.HasMorePages() {
				out, err := policyVersion.NextPage(ctx)
				if err != nil {
					if errors.As(err, &ae) && ae.ErrorCode() == "NoSuchEntity" {
						break
					}
					return handleAPIError(err)
				}
				for _, v := range out.Versions {
					if v.IsDefaultVersion {
						continue
					}
					if _, err = r.client.DeletePolicyVersion(ctx, &awsIamClient.DeletePolicyVersionInput{
						PolicyArn: &policyArn,
						VersionId: v.VersionId,
					}); err != nil && !(errors.As(err, &ae) && ae.ErrorCode() == "NoSuchEntity") {
						return handleAPIError(err)
					}
				}
			}

			if _, err := r.client.DeletePolicy(ctx, &awsIamClient.DeletePolicyInput{
				PolicyArn: &policyArn,
			}); err != nil && !(errors.As(err, &ae) && ae.ErrorCode() == "NoSuchEntity") {
				return handleAPIError(err)
			}
		}
		return nil
	}

	back := backoff.NewExponentialBackOff()
	back.MaxElapsedTime = 30 * time.Second
	if err := backoff.Retry(remove, back); err != nil {
		return append(unexpectedError, err)
	}
	return nil
}

// `ensurePolicyFullyDetached` detaches a customer-managed IAM policy from all principals (roles, users, groups) before deletion.
//
// Parameters:
//   - ctx      : Request context.
//   - policyArn: ARN of the policy to detach.
//
// Returns:
//   - error: nil on success; non-nil if AWS calls fail or any attachments remain after detaching.
func (r *iamPolicyV2Resource) ensurePolicyFullyDetached(ctx context.Context, policyArn string) error {
	if len(policyArn) < 20 {
		return nil
	}

	var ae smithy.APIError
	out, err := r.client.ListEntitiesForPolicy(ctx, &awsIamClient.ListEntitiesForPolicyInput{
		PolicyArn: aws.String(policyArn),
	})
	if err != nil {
		return handleAPIError(err)
	}

	// Detach from roles, users, and groups so policy deletion won’t fail with DeleteConflict if other attachments exist.
	// For role.
	for _, role := range out.PolicyRoles {
		_, derr := r.client.DetachRolePolicy(ctx, &awsIamClient.DetachRolePolicyInput{
			PolicyArn: aws.String(policyArn),
			RoleName:  role.RoleName,
		})
		if derr != nil && !(errors.As(derr, &ae) && ae.ErrorCode() == "NoSuchEntity") {
			return handleAPIError(derr)
		}
	}

	// For user.
	for _, user := range out.PolicyUsers {
		_, derr := r.client.DetachUserPolicy(ctx, &awsIamClient.DetachUserPolicyInput{
			PolicyArn: aws.String(policyArn),
			UserName:  user.UserName,
		})
		if derr != nil && !(errors.As(derr, &ae) && ae.ErrorCode() == "NoSuchEntity") {
			return handleAPIError(derr)
		}
	}

	// For group.
	for _, grp := range out.PolicyGroups {
		_, derr := r.client.DetachGroupPolicy(ctx, &awsIamClient.DetachGroupPolicyInput{
			PolicyArn: aws.String(policyArn),
			GroupName: grp.GroupName,
		})
		if derr != nil && !(errors.As(derr, &ae) && ae.ErrorCode() == "NoSuchEntity") {
			return handleAPIError(derr)
		}
	}

	out2, err := r.client.ListEntitiesForPolicy(ctx, &awsIamClient.ListEntitiesForPolicyInput{
		PolicyArn: aws.String(policyArn),
	})
	if err != nil {
		return handleAPIError(err)
	}
	if len(out2.PolicyRoles) > 0 || len(out2.PolicyUsers) > 0 || len(out2.PolicyGroups) > 0 {
		return fmt.Errorf("policy still attached to %d role(s), %d user(s), %d group(s)",
			len(out2.PolicyRoles), len(out2.PolicyUsers), len(out2.PolicyGroups))
	}
	return nil
}

// getPolicyArn resolves an IAM policy’s ARN and default version ID by its friendly name.
//
// Params:
//   - ctx        : request context
//   - policyName : friendly name to search
//
// Returns:
//   - policyArn, policyVersionId : empty if not found
//   - err                        : non-nil only if ListPolicies ultimately failed
func (r *iamPolicyV2Resource) getPolicyArn(ctx context.Context, policyName string) (policyArn string, policyVersionId string, err error) {
	var listPoliciesResponse *awsIamClient.ListPoliciesOutput

	listPolicies := func() error {
		listPoliciesResponse, err = r.client.ListPolicies(ctx, &awsIamClient.ListPoliciesInput{
			MaxItems: aws.Int32(1000),
			Scope:    "All",
		})
		if err != nil {
			return handleAPIError(err)
		}
		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second
	err = backoff.Retry(listPolicies, reconnectBackoff)

	for _, policyObj := range listPoliciesResponse.Policies {
		if *policyObj.PolicyName == policyName {
			policyArn = *policyObj.Arn
			policyVersionId = *policyObj.DefaultVersionId
		}
	}

	return policyArn, policyVersionId, err
}

// For role block.
// `attachPolicyToRole` attach the IAM policy to role through AWS SDK.
//
// Parameters:
//   - state: The recorded state configurations.
//
// Returns:
//   - err: Error.
func (r *iamPolicyV2Resource) attachPolicyToRole(ctx context.Context, state *iamPolicyV2ResourceModel) (unexpectedError []error) {
	attachPolicyToRole := func() error {
		for _, combinedPolicy := range state.CombinedPolicesDetail {
			policyArn, _, err := r.getPolicyArn(ctx, combinedPolicy.PolicyName.ValueString())

			if err != nil {
				unexpectedError = append(unexpectedError, err)
				continue
			}

			attachPolicyToRoleRequest := &awsIamClient.AttachRolePolicyInput{
				PolicyArn: aws.String(policyArn),
				RoleName:  aws.String(state.Role.RoleName.ValueString()),
			}

			if _, err := r.client.AttachRolePolicy(ctx, attachPolicyToRoleRequest); err != nil {
				return handleAPIError(err)
			}
		}
		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second
	if err := backoff.Retry(attachPolicyToRole, reconnectBackoff); err != nil {
		unexpectedError = append(unexpectedError, err)
	}

	return unexpectedError
}

// For user block.
// `attachPolicyToUser` attaches each combined customer-managed policy in state to the target IAM user.
//
// Parameters:
//   - ctx   : Request context.
//   - state : Current resource state (must include User and CombinedPolicesDetail).
//
// Returns:
//   - unexpectedError : Collected errors from ARN resolution or attach calls; nil if all succeeded.
func (r *iamPolicyV2Resource) attachPolicyToUser(ctx context.Context, state *iamPolicyV2ResourceModel) (unexpectedError []error) {
	attachPolicyToUser := func() error {
		for _, combinedPolicy := range state.CombinedPolicesDetail {
			policyArn, _, err := r.getPolicyArn(ctx, combinedPolicy.PolicyName.ValueString())

			if err != nil {
				unexpectedError = append(unexpectedError, err)
				continue
			}

			attachPolicyToUserRequest := &awsIamClient.AttachUserPolicyInput{
				PolicyArn: aws.String(policyArn),
				UserName:  aws.String(state.User.UserName.ValueString()),
			}

			if _, err := r.client.AttachUserPolicy(ctx, attachPolicyToUserRequest); err != nil {
				return handleAPIError(err)
			}
		}
		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second
	if err := backoff.Retry(attachPolicyToUser, reconnectBackoff); err != nil {
		unexpectedError = append(unexpectedError, err)
	}

	return unexpectedError
}

// For permission set block.
// `attachCustomerPoliciesToPermissionSet` attaches each combined customer-managed policy (by Name+Path)
// to the target Identity Center Permission Set.
//
// Parameters:
//   - ctx   : Request context.
//   - state : Must contain PermissionSet (InstanceArn, PermissionSetArn, PolicyPath) and CombinedPolicesDetail.
//
// Returns:
//   - unexpectedError : Collected non-retryable/validation errors; nil if all attachments succeeded or were conflicts.
func (r *iamPolicyV2Resource) attachCustomerPoliciesToPermissionSet(ctx context.Context, state *iamPolicyV2ResourceModel) (unexpectedError []error) {
	if r.sso == nil {
		return []error{fmt.Errorf("SSO Admin client is nil; ensure provider configured ssoadmin.Client")}
	}
	if state.PermissionSet.InstanceArn.IsNull() || state.PermissionSet.InstanceArn.IsUnknown() ||
		state.PermissionSet.PermissionSetArn.IsNull() || state.PermissionSet.PermissionSetArn.IsUnknown() {
		return []error{fmt.Errorf("instance_arn and permission_set_arn are required")}
	}
	if len(state.CombinedPolicesDetail) == 0 {
		return nil
	}

	attachFn := func() error {
		path := state.PermissionSet.PolicyPath.ValueString()
		if path == "" {
			path = "/"
		}

		var ae smithy.APIError

		for _, combinedPolicy := range state.CombinedPolicesDetail {
			input := &awsSsoAdminClient.AttachCustomerManagedPolicyReferenceToPermissionSetInput{
				InstanceArn:      aws.String(state.PermissionSet.InstanceArn.ValueString()),
				PermissionSetArn: aws.String(state.PermissionSet.PermissionSetArn.ValueString()),
				CustomerManagedPolicyReference: &ssoTypes.CustomerManagedPolicyReference{
					Name: aws.String(combinedPolicy.PolicyName.ValueString()),
					Path: aws.String(path),
				},
			}

			_, err := r.sso.AttachCustomerManagedPolicyReferenceToPermissionSet(ctx, input)
			if err == nil {
				continue
			}

			if errors.As(err, &ae) {
				switch ae.ErrorCode() {
				case "ConflictException":
					continue
				case "ThrottlingException", "TooManyRequestsException", "ServiceQuotaExceededException":
					return err
				case "AccessDeniedException", "ValidationException", "ResourceNotFoundException":
					unexpectedError = append(unexpectedError, handleAPIError(err))
					continue
				default:
					return handleAPIError(err)
				}
			}

			return handleAPIError(err)
		}

		return nil
	}

	back := backoff.NewExponentialBackOff()
	back.MaxElapsedTime = 30 * time.Second
	if err := backoff.Retry(attachFn, back); err != nil {
		unexpectedError = append(unexpectedError, err)
	}

	return unexpectedError
}

// `provisionPermissionSetAll` refreshes the given Permission Set across all
// already-provisioned accounts in the Identity Center instance, retrying the
// submission on transient errors with exponential backoff.
//
// Parameters:
//   - ctx   : Request context.
//   - state : Must contain PermissionSet.InstanceArn and PermissionSet.PermissionSetArn.
//
// Returns:
//   - unexpectedError : Collected errors if the provision call ultimately fails; nil on success.
func (r *iamPolicyV2Resource) provisionPermissionSetAll(ctx context.Context, state *iamPolicyV2ResourceModel) (unexpectedError []error) {
	if r.sso == nil {
		return []error{fmt.Errorf("SSO Admin client is nil; ensure provider configured ssoadmin.Client")}
	}
	prov := func() error {
		_, err := r.sso.ProvisionPermissionSet(ctx, &awsSsoAdminClient.ProvisionPermissionSetInput{
			InstanceArn:      aws.String(state.PermissionSet.InstanceArn.ValueString()),
			PermissionSetArn: aws.String(state.PermissionSet.PermissionSetArn.ValueString()),
			TargetType:       ssoTypes.ProvisionTargetTypeAllProvisionedAccounts,
		})
		if err != nil {
			return handleAPIError(err)
		}
		return nil
	}
	back := backoff.NewExponentialBackOff()
	back.MaxElapsedTime = 30 * time.Second
	if err := backoff.Retry(prov, back); err != nil {
		unexpectedError = append(unexpectedError, err)
	}
	return unexpectedError
}

// `attachAWSManagedPoliciesToPermissionSet` attaches a list of AWS-managed policy ARNs
// to the Permission Set's "AWS managed policies" section.
//
// Parameters:
//   - ctx   : Request context.
//   - state : Must contain PermissionSet.InstanceArn and PermissionSet.PermissionSetArn.
//   - awsManagedPolicyArns : ARNs of AWS-managed policies to attach.
//
// Returns:
//   - unexpectedError : Collected non-retryable/validation errors; nil if all attachments succeeded or were conflicts.
func (r *iamPolicyV2Resource) attachAWSManagedPoliciesToPermissionSet(ctx context.Context, state *iamPolicyV2ResourceModel, awsManagedPolicyArns []string) (unexpectedError []error) {
	if r.sso == nil {
		return []error{fmt.Errorf("SSO Admin client is nil; ensure provider configured ssoadmin.Client")}
	}
	if state.PermissionSet.InstanceArn.IsNull() || state.PermissionSet.InstanceArn.IsUnknown() ||
		state.PermissionSet.PermissionSetArn.IsNull() || state.PermissionSet.PermissionSetArn.IsUnknown() {
		return []error{fmt.Errorf("instance_arn and permission_set_arn are required")}
	}
	if len(awsManagedPolicyArns) == 0 {
		return nil
	}

	attachFn := func() error {
		var ae smithy.APIError
		for _, arnStr := range awsManagedPolicyArns {
			_, err := r.sso.AttachManagedPolicyToPermissionSet(ctx, &awsSsoAdminClient.AttachManagedPolicyToPermissionSetInput{
				InstanceArn:      aws.String(state.PermissionSet.InstanceArn.ValueString()),
				PermissionSetArn: aws.String(state.PermissionSet.PermissionSetArn.ValueString()),
				ManagedPolicyArn: aws.String(arnStr),
			})
			if err == nil {
				continue
			}
			if errors.As(err, &ae) {
				switch ae.ErrorCode() {
				case "ConflictException":
					continue
				case "ThrottlingException", "TooManyRequestsException", "ServiceQuotaExceededException":
					return err
				case "AccessDeniedException", "ValidationException", "ResourceNotFoundException":
					unexpectedError = append(unexpectedError, handleAPIError(err))
					continue
				default:
					return handleAPIError(err)
				}
			}
			return handleAPIError(err)
		}
		return nil
	}

	back := backoff.NewExponentialBackOff()
	back.MaxElapsedTime = 30 * time.Second
	if err := backoff.Retry(attachFn, back); err != nil {
		unexpectedError = append(unexpectedError, err)
	}
	return unexpectedError
}

// `detachCustomerPoliciesFromPermissionSet` removes selected CUSTOMER-managed policy references from a Permission Set.
//
// Parameters:
//   - ctx   : Request context.
//   - state : Must contain PermissionSet (InstanceArn, PermissionSetArn, PolicyPath) and CombinedPolicesDetail.
//
// Returns:
//   - unexpectedError : Collected non-retryable errors; nil if all needed detaches succeeded or were benign.
func (r *iamPolicyV2Resource) detachCustomerPoliciesFromPermissionSet(ctx context.Context, state *iamPolicyV2ResourceModel) (unexpectedError []error) {
	if r.sso == nil {
		return []error{fmt.Errorf("SSO Admin client is nil; ensure provider configured ssoadmin.Client")}
	}
	if state.PermissionSet.InstanceArn.IsNull() || state.PermissionSet.InstanceArn.IsUnknown() ||
		state.PermissionSet.PermissionSetArn.IsNull() || state.PermissionSet.PermissionSetArn.IsUnknown() {
		return []error{fmt.Errorf("instance_arn and permission_set_arn are required to detach policies")}
	}

	want := map[string]struct{}{}
	for _, cp := range state.CombinedPolicesDetail {
		want[cp.PolicyName.ValueString()] = struct{}{}
	}

	listAndDetach := func() error {
		path := state.PermissionSet.PolicyPath.ValueString()
		if path == "" {
			path = "/"
		}

		var ae smithy.APIError
		out, err := r.sso.ListCustomerManagedPolicyReferencesInPermissionSet(ctx,
			&awsSsoAdminClient.ListCustomerManagedPolicyReferencesInPermissionSetInput{
				InstanceArn:      aws.String(state.PermissionSet.InstanceArn.ValueString()),
				PermissionSetArn: aws.String(state.PermissionSet.PermissionSetArn.ValueString()),
			})
		if err != nil {
			if errors.As(err, &ae) && (ae.ErrorCode() == "ThrottlingException" || ae.ErrorCode() == "TooManyRequestsException") {
				return err
			}
			return handleAPIError(err)
		}

		for _, ref := range out.CustomerManagedPolicyReferences {
			if ref.Name == nil {
				continue
			}
			name := *ref.Name
			if _, ok := want[name]; !ok {
				continue
			}
			_, err := r.sso.DetachCustomerManagedPolicyReferenceFromPermissionSet(ctx,
				&awsSsoAdminClient.DetachCustomerManagedPolicyReferenceFromPermissionSetInput{
					InstanceArn:      aws.String(state.PermissionSet.InstanceArn.ValueString()),
					PermissionSetArn: aws.String(state.PermissionSet.PermissionSetArn.ValueString()),
					CustomerManagedPolicyReference: &ssoTypes.CustomerManagedPolicyReference{
						Name: aws.String(name),
						Path: aws.String(path),
					},
				})
			if err != nil {
				if errors.As(err, &ae) {
					switch ae.ErrorCode() {
					case "ResourceNotFoundException", "ConflictException":
						continue
					case "ThrottlingException", "TooManyRequestsException":
						return err
					}
				}
				unexpectedError = append(unexpectedError, handleAPIError(err))
				continue
			}
		}
		return nil
	}

	back := backoff.NewExponentialBackOff()
	back.MaxElapsedTime = 30 * time.Second
	if err := backoff.Retry(listAndDetach, back); err != nil {
		unexpectedError = append(unexpectedError, err)
	}
	return unexpectedError
}
