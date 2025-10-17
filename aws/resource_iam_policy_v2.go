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
	"github.com/hashicorp/terraform-plugin-framework/diag"
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
	PermissionSetName types.String `tfsdk:"permission_set_name"`
	InstanceArn       types.String `tfsdk:"instance_arn"`
	PermissionSetArn  types.String `tfsdk:"permission_set_arn"`
	PolicyPath        types.String `tfsdk:"policy_path"`
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
				Description: "Attach to an IAM Role. Mutually exclusive with `user` and `permission_set`.",
				Attributes: map[string]schema.Attribute{
					"role_name": schema.StringAttribute{
						Description: "Target IAM Role name.",
						Optional:    true,
					},
				},
			},
			"user": schema.SingleNestedBlock{
				Description: "Attach to an IAM User. Mutually exclusive with `role` and `permission_set`.",
				Attributes: map[string]schema.Attribute{
					"user_name": schema.StringAttribute{
						Description: "Target IAM User name.",
						Optional:    true,
					},
				},
			},
			"permission_set": schema.SingleNestedBlock{
				Description: "Attach to an Identity Center Permission Set. Mutually exclusive with `role` and `user`.",
				Attributes: map[string]schema.Attribute{
					"permission_set_name": schema.StringAttribute{
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

func (r *iamPolicyV2Resource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// If the entire plan is null, the resource is planned for destruction.
	if req.Config.Raw.IsNull() {
		fmt.Println("Plan is null; skipping ModifyPlan.")
		return
	}

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

	// Check if PermissionSet block is config. Set default path "/".
	if plan.PermissionSet != nil {
		if plan.PermissionSet.PolicyPath.IsNull() || plan.PermissionSet.PolicyPath.IsUnknown() || plan.PermissionSet.PolicyPath.ValueString() == "" {
			plan.PermissionSet.PolicyPath = types.StringValue("/") // The default policy path is "/".
		}
	}
}

func (r *iamPolicyV2Resource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan *iamPolicyV2ResourceModel
	getPlanDiags := req.Config.Get(ctx, &plan)
	resp.Diagnostics.Append(getPlanDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	combinedPolicies, attachedPolicies, errors := r.createPolicy(ctx, plan)
	addDiagnostics(
		&resp.Diagnostics,
		"error",
		"[API ERROR] Failed to Create the Policy.",
		errors,
		"",
	)
	if resp.Diagnostics.HasError() {
		return
	}

	state := &iamPolicyV2ResourceModel{
		AttachedPolicies:       plan.AttachedPolicies,
		AttachedPoliciesDetail: attachedPolicies,
		CombinedPolicesDetail:  combinedPolicies,
		Role:                   plan.Role,
		User:                   plan.User,
		PermissionSet:          plan.PermissionSet,
	}

	assigneeType, assigneeName := assigneeTypeOf(plan)

	var attachErrs []error
	switch assigneeType {
	case "role":
		attachErrs = r.attachPolicyToRole(ctx, state)
	case "user":
		attachErrs = r.attachPolicyToUser(ctx, state)
	case "permissionSet":
		attachErrs = r.attachPolicyToPermissionSet(ctx, state, 10*time.Minute)
	default:
		attachErrs = []error{fmt.Errorf("no valid target (role/user/permission_set) in plan")}
	}
	if len(attachErrs) > 0 {
		addDiagnostics(&resp.Diagnostics, "error", "[API ERROR] Failed to Attach Policy to target.", attachErrs, "")
		return
	}

	// Create policy are not expected to have not found warning.
	readCombinedPolicyNotExistErr, readCombinedPolicyErr := r.readCombinedPolicy(ctx, state)
	addReadCombinedDiags(&resp.Diagnostics, assigneeName, readCombinedPolicyNotExistErr, readCombinedPolicyErr)
	if resp.Diagnostics.HasError() {
		return
	}

	setStateDiags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *iamPolicyV2Resource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state *iamPolicyV2ResourceModel
	getStateDiags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(getStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// This state will be using to compare with the current state.
	var oriState *iamPolicyV2ResourceModel
	getOriStateDiags := req.State.Get(ctx, &oriState)
	resp.Diagnostics.Append(getOriStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, assigneeName := assigneeTypeOf(state)

	readCombinedPolicyNotExistErr, readCombinedPolicyErr := r.readCombinedPolicy(ctx, state)
	addReadCombinedDiags(&resp.Diagnostics, assigneeName, readCombinedPolicyNotExistErr, readCombinedPolicyErr)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set state so that Terraform will trigger update if there are changes in state.
	setStateDiags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.WarningsCount() > 0 || resp.Diagnostics.HasError() {
		return
	}

	// If the attached policy not found, it should return warning instead of error
	// because there is no ways to get plan configuration in Read() function to
	// indicate user had removed the non existed policies from the input.
	readAttachedPolicyNotExistErr, readAttachedPolicyErr := r.readAttachedPolicy(ctx, state)
	addReadCombinedDiags(&resp.Diagnostics, assigneeName, readAttachedPolicyNotExistErr, readAttachedPolicyErr)

	// Set state so that Terraform will trigger update if there are changes in state.
	setStateDiags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.WarningsCount() > 0 || resp.Diagnostics.HasError() {
		return
	}

	compareAttachedPoliciesErr := r.checkPoliciesDrift(state, oriState)
	addDiagnostics(
		&resp.Diagnostics,
		"warning",
		fmt.Sprintf("[API WARNING] Policy Drift Detected for %v.", assigneeName),
		[]error{compareAttachedPoliciesErr},
		"This resource will be updated in the next terraform apply.",
	)

	setStateDiags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read the attached policy. -> If got changes, remove policy. -> Create the policy again. -> Attach to the targets.
func (r *iamPolicyV2Resource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state *iamPolicyV2ResourceModel
	getPlanDiags := req.Config.Get(ctx, &plan)
	resp.Diagnostics.Append(getPlanDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	getStateDiags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(getStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, assigneeName := assigneeTypeOf(state)

	// readAttachedPolicy.
	readAttachedPolicyNotExistErr, readAttachedPolicyErr := r.readAttachedPolicy(ctx, plan)
	addReadCombinedDiags(&resp.Diagnostics, assigneeName, readAttachedPolicyNotExistErr, readAttachedPolicyErr)
	if resp.Diagnostics.HasError() {
		return
	}

	// removePolicy.
	removePolicyErr := r.removePolicy(ctx, state)
	addDiagnostics(
		&resp.Diagnostics,
		"error",
		fmt.Sprintf("[API ERROR] Failed to Remove Policies for %v: Unexpected Error!", assigneeName),
		removePolicyErr,
		"",
	)
	if resp.Diagnostics.HasError() {
		return
	}

	state.CombinedPolicesDetail = nil
	setStateDiags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// createPolicy.
	combinedPolicies, attachedPolicies, errors := r.createPolicy(ctx, plan)
	addDiagnostics(
		&resp.Diagnostics,
		"error",
		"[API ERROR] Failed to Create the Policy.",
		errors,
		"",
	)
	if resp.Diagnostics.HasError() {
		return
	}

	state = &iamPolicyV2ResourceModel{
		AttachedPolicies:       plan.AttachedPolicies,
		AttachedPoliciesDetail: attachedPolicies,
		CombinedPolicesDetail:  combinedPolicies,
		Role:                   plan.Role,
		User:                   plan.User,
		PermissionSet:          plan.PermissionSet,
	}

	assigneeType, assigneeName := assigneeTypeOf(plan)

	var attachPolicyToUserErr []error
	switch assigneeType {
	case "role":
		attachPolicyToUserErr = r.attachPolicyToRole(ctx, state)
	case "user":
		attachPolicyToUserErr = r.attachPolicyToUser(ctx, state)
	case "permissionSet":
		attachPolicyToUserErr = r.attachPolicyToPermissionSet(ctx, state, 10*time.Minute)
	default:
		attachPolicyToUserErr = []error{fmt.Errorf("no valid target (role/user/permission_set) in plan")}
	}
	if len(attachPolicyToUserErr) > 0 {
		addDiagnostics(&resp.Diagnostics, "error", "[API ERROR] Failed to Attach Policy to target.", attachPolicyToUserErr, "")
		return
	}

	readCombinedPolicyNotExistErr, readCombinedPolicyErr := r.readCombinedPolicy(ctx, state)
	addReadCombinedDiags(&resp.Diagnostics, assigneeName, readCombinedPolicyNotExistErr, readCombinedPolicyErr)
	if resp.Diagnostics.HasError() {
		return
	}

	setStateDiags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *iamPolicyV2Resource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state *iamPolicyV2ResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// readAttachedPolicy.
	_, readAssigneeName := assigneeTypeOf(state)
	readAttachedPolicyNotExistErr, readAttachedPolicyErr := r.readAttachedPolicy(ctx, state)
	addReadCombinedDiags(&resp.Diagnostics, readAssigneeName, readAttachedPolicyNotExistErr, readAttachedPolicyErr)
	if resp.Diagnostics.HasError() {
		return
	}

	// removePolicy.
	removePolicyErr := r.removePolicy(ctx, state)
	_, removePolicyName := assigneeTypeOf(state)
	addDiagnostics(
		&resp.Diagnostics,
		"error",
		fmt.Sprintf("[API ERROR] Failed to Remove Policies for %v: Unexpected Error!", removePolicyName),
		removePolicyErr,
		"",
	)
	if resp.Diagnostics.HasError() {

		return
	}
}

// createPolicy will create the combined policy and return the attached policies
// details to be saved in state for comparing in Read() function.
//
// Parameters:
//   - ctx: Context.
//   - plan: Terraform plan configurations.
//
// Returns:
//   - combinedPoliciesDetail: The combined policies detail to be recorded in state file.
//   - attachedPoliciesDetail: The attached policies detail to be recorded in state file.
//   - errList: List of errors, return nil if no errors.
func (r *iamPolicyV2Resource) createPolicy(ctx context.Context, plan *iamPolicyV2ResourceModel) (combinedPoliciesDetail []*policyV2Detail, attachedPoliciesDetail []*policyV2Detail, errList []error) {
	var policies []string
	plan.AttachedPolicies.ElementsAs(ctx, &policies, false)
	combinedPolicyDocuments, excludedPolicies, attachedPoliciesDetail, errList := r.combinePolicyDocument(ctx, policies)
	if errList != nil {
		return nil, nil, errList
	}

	assigneeType, prefix := assigneeTypeOf(plan)
	pathPtr := (*string)(nil)
	usePath := false

	if assigneeType == "permissionSet" &&
		plan.PermissionSet != nil &&
		plan.PermissionSet.PolicyPath.ValueString() != "" {

		path := plan.PermissionSet.PolicyPath.ValueString()
		pathPtr = &path
		usePath = true
	}

	createPolicy := func() error {
		for i, policy := range combinedPolicyDocuments {
			policyName := fmt.Sprintf("%s-%d", prefix, i+1)

			createPolicyRequest := &awsIamClient.CreatePolicyInput{
				PolicyName:     aws.String(policyName),
				PolicyDocument: aws.String(policy),
			}
			if usePath {
				createPolicyRequest.Path = pathPtr
			}

			if _, err := r.client.CreatePolicy(ctx, createPolicyRequest); err != nil {
				return handleAPIError(err)
			}
		}

		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second
	err := backoff.Retry(createPolicy, reconnectBackoff)

	if err != nil {
		return nil, nil, []error{err}
	}

	for i, policies := range combinedPolicyDocuments {
		policyName := fmt.Sprintf("%s-%d", prefix, i+1)

		combinedPoliciesDetail = append(combinedPoliciesDetail, &policyV2Detail{
			PolicyName:     types.StringValue(policyName),
			PolicyDocument: types.StringValue(policies),
		})
	}

	// These policies will be attached directly to the user since splitting the
	// policy "statement" will be hitting the limitation of "maximum number of
	// attached policies" easily.
	combinedPoliciesDetail = append(combinedPoliciesDetail, excludedPolicies...)

	return combinedPoliciesDetail, attachedPoliciesDetail, nil
}

// combinePolicyDocument combine the policy with custom logic.
//
// Parameters:
//   - ctx: Context.
//   - attachedPolicies: List of user attached policies to be combined.
//
// Returns:
//   - combinedPolicyDocument: The completed policy document after combining attached policies.
//   - excludedPolicies: If the target policy exceeds maximum length, then do not combine the policy and return as excludedPolicies.
//   - attachedPoliciesDetail: The attached policies detail to be recorded in state file.
//   - errList: List of errors, return nil if no errors.
func (r *iamPolicyV2Resource) combinePolicyDocument(ctx context.Context, attachedPolicies []string) (combinedPolicyDocument []string, excludedPolicies []*policyV2Detail, attachedPoliciesDetail []*policyV2Detail, errList []error) {
	attachedPoliciesDetail, notExistErrList, unexpectedErrList := r.fetchPolicies(ctx, attachedPolicies)

	errList = append(errList, notExistErrList...)
	errList = append(errList, unexpectedErrList...)

	if len(errList) != 0 {
		return nil, nil, nil, errList
	}

	currentLength := 0
	currentPolicyDocument := ""
	appendedPolicyDocument := make([]string, 0)

	for _, attachedPolicy := range attachedPoliciesDetail {
		tempPolicyDocument, err := url.QueryUnescape(attachedPolicy.PolicyDocument.ValueString())
		if err != nil {
			errList = append(errList, err)
			return nil, nil, nil, errList
		}
		// If the policy itself have more than 6144 characters, then skip the combine
		// policy part since splitting the policy "statement" will be hitting the
		// limitation of "maximum number of attached policies" easily.
		noWhitespace := strings.Join(strings.Fields(tempPolicyDocument), "") //removes any whitespace including \t and \n
		if len(noWhitespace) > policyMaxLength {
			excludedPolicies = append(excludedPolicies, &policyV2Detail{
				PolicyName:     attachedPolicy.PolicyName,
				PolicyDocument: types.StringValue(tempPolicyDocument),
			})
			continue
		}

		var data map[string]interface{}
		if err := json.Unmarshal([]byte(tempPolicyDocument), &data); err != nil {
			errList = append(errList, err)
			return nil, nil, nil, errList
		}

		statementBytes, err := json.Marshal(data["Statement"])
		if err != nil {
			errList = append(errList, err)
			return nil, nil, nil, errList
		}

		finalStatement := strings.Trim(string(statementBytes), "[]")
		currentLength += len(finalStatement)

		// Before further proceeding the current policy, we need to add a number
		// of 'policyKeywordLength' to simulate the total length of completed
		// policy to check whether it is already execeeded the max character
		// length of 6144.
		if (currentLength + policyV2KeywordLength) > policyV2MaxLength {
			currentPolicyDocument = strings.TrimSuffix(currentPolicyDocument, ",")
			appendedPolicyDocument = append(appendedPolicyDocument, currentPolicyDocument)
			currentPolicyDocument = finalStatement + ","
			currentLength = len(finalStatement)
		} else {
			currentPolicyDocument += finalStatement + ","
		}
	}

	if len(currentPolicyDocument) > 0 {
		currentPolicyDocument = strings.TrimSuffix(currentPolicyDocument, ",")
		appendedPolicyDocument = append(appendedPolicyDocument, currentPolicyDocument)
	}

	for _, policyStatement := range appendedPolicyDocument {
		combinedPolicyDocument = append(combinedPolicyDocument, fmt.Sprintf(`{"Version":"2012-10-17","Statement":[%v]}`, policyStatement))
	}

	return combinedPolicyDocument, excludedPolicies, attachedPoliciesDetail, nil
}

// readCombinedPolicy will read the combined policy details.
//
// Parameters:
//   - state: The state configurations, it will directly update the value of the struct since it is a pointer.
//
// Returns:
//   - notExistError: List of allowed not exist errors to be used as warning messages instead, return nil if no errors.
//   - unexpectedError: List of unexpected errors to be used as normal error messages, return nil if no errors.
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

// readAttachedPolicy will read the attached policy details.
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

// fetchPolicies retrieve policy document through AWS SDK with backoff retry.
//
// Parameters:
//   - policiesName: List of IAM policies name.
//
// Returns:
//   - policiesDetail: List of retrieved policies detail.
//   - notExistError: List of allowed not exist errors to be used as warning messages instead, return empty list if no errors.
//   - unexpectedError: List of unexpected errors to be used as normal error messages, return empty list if no errors.
func (r *iamPolicyV2Resource) fetchPolicies(ctx context.Context, policiesName []string) (policiesDetail []*policyV2Detail, notExistError, unexpectedError []error) {
	getPolicyDocumentResponse := &awsIamClient.GetPolicyVersionOutput{}
	getPolicyNameResponse := &awsIamClient.GetPolicyOutput{}
	var ae smithy.APIError

	for _, attachedPolicy := range policiesName {
		policyArn, policyVersionId, err := r.getPolicyArn(ctx, attachedPolicy)

		if err != nil {
			unexpectedError = append(unexpectedError, err)
			continue
		}

		if policyArn == "" && policyVersionId == "" {
			notExistError = append(notExistError, fmt.Errorf("policy %v does not exist", attachedPolicy))
			continue
		}

		getPolicy := func() error {
			getPolicyDocumentRequest := &awsIamClient.GetPolicyVersionInput{
				PolicyArn: aws.String(policyArn),
				VersionId: aws.String(policyVersionId),
			}

			getPolicyDocumentResponse, err = r.client.GetPolicyVersion(ctx, getPolicyDocumentRequest)
			if err != nil {
				return handleAPIError(err)
			}

			getPolicyNameRequest := &awsIamClient.GetPolicyInput{
				PolicyArn: aws.String(policyArn),
			}

			getPolicyNameResponse, err = r.client.GetPolicy(ctx, getPolicyNameRequest)
			if err != nil {
				return handleAPIError(err)
			}
			return nil
		}

		reconnectBackoff := backoff.NewExponentialBackOff()
		reconnectBackoff.MaxElapsedTime = 30 * time.Second
		err = backoff.Retry(getPolicy, reconnectBackoff)

		// Handle permanent error returned from API.
		if err != nil && errors.As(err, &ae) {
			switch ae.ErrorCode() {
			case "NoSuchEntity":
				notExistError = append(notExistError, err)
			default:
				unexpectedError = append(unexpectedError, err)
			}
		} else {
			policiesDetail = append(policiesDetail, &policyV2Detail{
				PolicyName:     types.StringValue(*getPolicyNameResponse.Policy.PolicyName),
				PolicyDocument: types.StringValue(*getPolicyDocumentResponse.PolicyVersion.Document),
			})
		}
	}

	return
}

// checkPoliciesDrift compare the recorded AttachedPoliciesDetail documents with
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

// removePolicy will detach and delete the combined policies from user.
//
// Parameters:
//   - state: The recorded state configurations.
func (r *iamPolicyV2Resource) removePolicy(ctx context.Context, state *iamPolicyV2ResourceModel) (unexpectedError []error) {
	var ae smithy.APIError
	var listPolicyVersionsResponse *awsIamClient.ListPolicyVersionsOutput

	removePolicy := func() error {
		for _, combinedPolicy := range state.CombinedPolicesDetail {
			policyArn, _, err := r.getPolicyArn(ctx, combinedPolicy.PolicyName.ValueString())
			if err != nil {
				unexpectedError = append(unexpectedError, err)
				continue
			}

			switch {
			case state.Role != nil:

				if _, err := r.client.DetachRolePolicy(ctx, &awsIamClient.DetachRolePolicyInput{
					PolicyArn: aws.String(policyArn),
					RoleName:  aws.String(state.Role.RoleName.ValueString()),
				}); err != nil && !(errors.As(err, &ae) && ae.ErrorCode() == "NoSuchEntity") {
					return handleAPIError(err)
				}

			case state.User != nil:

				if _, err := r.client.DetachUserPolicy(ctx, &awsIamClient.DetachUserPolicyInput{
					PolicyArn: aws.String(policyArn),
					UserName:  aws.String(state.User.UserName.ValueString()),
				}); err != nil && !(errors.As(err, &ae) && ae.ErrorCode() == "NoSuchEntity") {
					return handleAPIError(err)
				}

			case state.PermissionSet != nil:

				instanceArn := state.PermissionSet.InstanceArn.ValueString()
				psArn := state.PermissionSet.PermissionSetArn.ValueString()

				a, err := arn.Parse(policyArn)
				if err != nil {
					continue
				}

				if a.AccountID == "aws" {
					if _, err := r.sso.DetachManagedPolicyFromPermissionSet(ctx, &awsSsoAdminClient.DetachManagedPolicyFromPermissionSetInput{
						InstanceArn:      aws.String(instanceArn),
						PermissionSetArn: aws.String(psArn),
						ManagedPolicyArn: aws.String(policyArn),
					}); err != nil {
						if errors.As(err, &ae) {
							if ae.ErrorCode() == "ResourceNotFoundException" || ae.ErrorCode() == "ValidationException" {
							} else {
								return handleAPIError(err)
							}
						} else {
							return handleAPIError(err)
						}
					}
				} else {
					if detErr := errors.Join(r.detachCustomerPoliciesFromPermissionSet(ctx, state)...); detErr != nil {
						return fmt.Errorf("[API ERROR] Failed to detach customer-managed policies from Permission Set: %w", detErr)
					}

				}

				if ok, errs := r.provisionPermissionSetAllWait(ctx, state, 10*time.Minute); !ok {
					return fmt.Errorf("[API ERROR] Provisioning did not complete: %w", errors.Join(errs...))
				}

			}

			a, err := arn.Parse(policyArn)
			if err != nil {
				continue
			}

			// The arn difference between AWS managed policy and customer managed policies:
			// AWS managed policy: arn:aws:iam::*aws*:policy/XxxxXxxxx
			// Customer managed policy: arn:aws:iam::*xxxxxxxxxxxx*:policy/xxxx-xxx-xxxx-xxxx-xxx-xx
			// See http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html for more information.
			// To differentiate is the ** part, the part is AccountID field.
			if a.AccountID == "aws" {
				continue
			}

			listPolicyVersionsRequest := &awsIamClient.ListPolicyVersionsInput{
				PolicyArn: aws.String(policyArn),
			}

			// An IAM policy versions must be removed before deleting
			// the policy. Refer to the below offcial IAM documents:
			// https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeletePolicy.html
			if listPolicyVersionsResponse, err = r.client.ListPolicyVersions(ctx, listPolicyVersionsRequest); err != nil {
				if errors.As(err, &ae) {
					// Ignore error where the policy version does
					// not exists in the policy as it was intended
					// to delete the policy version.
					if ae.ErrorCode() != "NoSuchEntity" {
						return handleAPIError(err)
					}
				}
			}

			for _, policyVersion := range listPolicyVersionsResponse.Versions {
				// Default version could not be deleted.
				if policyVersion.IsDefaultVersion {
					continue
				}
				deletePolicyVersionRequest := &awsIamClient.DeletePolicyVersionInput{
					PolicyArn: aws.String(policyArn),
					VersionId: aws.String(*policyVersion.VersionId),
				}

				if _, err = r.client.DeletePolicyVersion(ctx, deletePolicyVersionRequest); err != nil {
					// Ignore error where the policy version does
					// not exists in the policy as it was intended
					// to delete the policy version.
					if errors.As(err, &ae) && ae.ErrorCode() != "NoSuchEntity" {
						return handleAPIError(err)
					}
				}
			}

			deletePolicyRequest := &awsIamClient.DeletePolicyInput{
				PolicyArn: aws.String(policyArn),
			}

			if _, err = r.client.DeletePolicy(ctx, deletePolicyRequest); err != nil {
				// Ignore error where the policy had been deleted
				// as it is intended to delete the IAM policy.
				if errors.As(err, &ae) && ae.ErrorCode() != "NoSuchEntity" {
					return handleAPIError(err)
				}
			}
		}
		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second
	err := backoff.Retry(removePolicy, reconnectBackoff)
	if err != nil {
		return append(unexpectedError, err)
	}

	return nil
}

// attachPolicyToRole attach the IAM policy to role through AWS SDK.
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

// attachPolicyToUser attach the IAM policy to user through AWS SDK.
//
// Parameters:
//   - state: The recorded state configurations.
//
// Returns:
//   - err: Error.
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

// attachCustomerPoliciesToPermissionSet attaches the given customer-managed IAM policies
// (identified by Name + Path) to the target AWS IAM Identity Center (SSO) Permission Set.
//
// Parameters:
//   - ctx: request context (cancellation/deadline honored by retries)
//   - state: model containing the Permission Set identifiers and path
//   - policies: list of policy details to attach (names taken from PolicyName.ValueString())
//
// Returns:
//   - err: Error.
func (r *iamPolicyV2Resource) attachCustomerPoliciesToPermissionSet(ctx context.Context, state *iamPolicyV2ResourceModel, policies []*policyV2Detail) (unexpectedError []error) {
	attachCustomerPoliciesToPermissionSet := func() error {
		path := state.PermissionSet.PolicyPath.ValueString()
		if path == "" {
			path = "/"
		}

		for _, policy := range policies {
			attachCustomerManagedPoliciesReferenceToPermissionSetInputRequest := &awsSsoAdminClient.AttachCustomerManagedPolicyReferenceToPermissionSetInput{
				InstanceArn:      aws.String(state.PermissionSet.InstanceArn.ValueString()),
				PermissionSetArn: aws.String(state.PermissionSet.PermissionSetArn.ValueString()),
				CustomerManagedPolicyReference: &ssoTypes.CustomerManagedPolicyReference{
					Name: aws.String(policy.PolicyName.ValueString()),
					Path: aws.String(path),
				},
			}

			if _, err := r.sso.AttachCustomerManagedPolicyReferenceToPermissionSet(ctx, attachCustomerManagedPoliciesReferenceToPermissionSetInputRequest); err != nil {
				return handleAPIError(err)
			}
		}

		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second
	if err := backoff.Retry(attachCustomerPoliciesToPermissionSet, reconnectBackoff); err != nil {
		unexpectedError = append(unexpectedError, err)
	}

	return unexpectedError
}

// attachAWSManagedPoliciesToPermissionSet attaches the provided AWS-managed policy ARNs
// to the target AWS IAM Identity Center (SSO) Permission Set.
//
// Parameters
//   - ctx: request context (cancellation/deadline honored by retries)
//   - state: model containing the Permission Set identifiers
//   - awsManagedPolicyArns: list of AWS-managed policy ARNs to attach
//
// Returns:
//   - err: Error.

func (r *iamPolicyV2Resource) attachAWSManagedPoliciesToPermissionSet(ctx context.Context, state *iamPolicyV2ResourceModel, awsManagedPolicyArns []string) (unexpectedError []error) {
	attachAWSManagedPoliciesToPermissionSet := func() error {
		for _, awsManagedPolicyArn := range awsManagedPolicyArns {
			attachManagedPolicyToPermissionSetInputRequest := &awsSsoAdminClient.AttachManagedPolicyToPermissionSetInput{
				InstanceArn:      aws.String(state.PermissionSet.InstanceArn.ValueString()),
				PermissionSetArn: aws.String(state.PermissionSet.PermissionSetArn.ValueString()),
				ManagedPolicyArn: aws.String(awsManagedPolicyArn),
			}

			if _, err := r.sso.AttachManagedPolicyToPermissionSet(ctx, attachManagedPolicyToPermissionSetInputRequest); err != nil {
				return handleAPIError(err)
			}
		}
		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second
	if err := backoff.Retry(attachAWSManagedPoliciesToPermissionSet, reconnectBackoff); err != nil {
		unexpectedError = append(unexpectedError, err)
	}
	return unexpectedError
}

// attachPolicyToPermissionSet attaches both customer-managed (combined) and AWS-managed policies
// to the target AWS IAM Identity Center (SSO) Permission Set, then provisions the Permission Set
// across all provisioned accounts.
//
// Parameters
//   - ctx: request context (cancellation/deadline honored by retries)
//   - state: model containing Permission Set identifiers and CombinedPolicesDetail
//   - provisionTimeout: maximum time to wait for provisioning to reach SUCCEEDED
//
// Returns:
//   - err: Error.
func (r *iamPolicyV2Resource) attachPolicyToPermissionSet(ctx context.Context, state *iamPolicyV2ResourceModel, provisionTimeout time.Duration) (unexpectedErrs []error) {
	if len(state.CombinedPolicesDetail) == 0 {
		if ok, errs := r.provisionPermissionSetAllWait(ctx, state, provisionTimeout); !ok {
			return append(unexpectedErrs, errs...)
		}
		return nil
	}

	prefix := state.PermissionSet.PermissionSetName.ValueString() + "-"

	var customerManagedPolicy []*policyV2Detail
	var awsManagedPolicy []*policyV2Detail

	for _, combinedPolicy := range state.CombinedPolicesDetail {
		if strings.HasPrefix(combinedPolicy.PolicyName.ValueString(), prefix) {
			customerManagedPolicy = append(customerManagedPolicy, combinedPolicy)
		} else {
			awsManagedPolicy = append(awsManagedPolicy, combinedPolicy)
		}
	}

	// Attach customer-managed policy.
	if len(customerManagedPolicy) > 0 {
		if errs := r.attachCustomerPoliciesToPermissionSet(ctx, state, customerManagedPolicy); len(errs) > 0 {
			unexpectedErrs = append(unexpectedErrs, errs...)
		}
	}

	// Attach AWS-managed policy.
	if len(awsManagedPolicy) > 0 {
		awsManagedArns := make([]string, 0, len(awsManagedPolicy))
		var resolvedArnErrs []error

		for _, awsManagedPolicyArn := range awsManagedPolicy {
			resolvedArn, _, err := r.getPolicyArn(ctx, awsManagedPolicyArn.PolicyName.ValueString())
			if err != nil || resolvedArn == "" {
				if err == nil {
					err = fmt.Errorf("policy %q not found", awsManagedPolicyArn.PolicyName.ValueString())
				}
				resolvedArnErrs = append(resolvedArnErrs, handleAPIError(err))
				continue
			}
			awsManagedArns = append(awsManagedArns, resolvedArn)
		}

		if len(resolvedArnErrs) > 0 {
			unexpectedErrs = append(unexpectedErrs, resolvedArnErrs...)
		}

		if len(awsManagedArns) > 0 {
			if awsManagedArnsErrs := r.attachAWSManagedPoliciesToPermissionSet(ctx, state, awsManagedArns); len(awsManagedArnsErrs) > 0 {
				unexpectedErrs = append(unexpectedErrs, awsManagedArnsErrs...)
			}
		}
	}

	if ok, errs := r.provisionPermissionSetAllWait(ctx, state, provisionTimeout); !ok {
		unexpectedErrs = append(unexpectedErrs, errs...)
	}

	return unexpectedErrs
}

// provisionPermissionSetAllWait triggers provisioning of the Permission Set to all
// provisioned accounts and waits until the request reaches SUCCEEDED (or fails/timeouts).
// Every time having changes will need to provision again to all accounts.
//
// Parameters
//   - ctx: request context (cancellation/deadline honored in retries).
//   - state: model containing Permission Set identifiers (InstanceArn, PermissionSetArn).
//   - maxWait: maximum total time to wait for the provisioning status to reach SUCCEEDED.
//
// Returns
//   - ok: true if provisioning completed with SUCCEEDED; false otherwise.
//   - err: Error.
func (r *iamPolicyV2Resource) provisionPermissionSetAllWait(ctx context.Context, state *iamPolicyV2ResourceModel, maxWait time.Duration) (ok bool, unexpectedError []error) {
	var reqID string
	provisionPermissionSetRequest := func() error {
		provisionPermissionSet, err := r.sso.ProvisionPermissionSet(ctx, &awsSsoAdminClient.ProvisionPermissionSetInput{
			InstanceArn:      aws.String(state.PermissionSet.InstanceArn.ValueString()),
			PermissionSetArn: aws.String(state.PermissionSet.PermissionSetArn.ValueString()),
			TargetType:       ssoTypes.ProvisionTargetTypeAllProvisionedAccounts,
		})
		if err != nil {
			var ae smithy.APIError
			if errors.As(err, &ae) && (ae.ErrorCode() == "ThrottlingException" || ae.ErrorCode() == "TooManyRequestsException" || ae.ErrorCode() == "ProvisioningInProgressException") {
				return err
			}
			return backoff.Permanent(handleAPIError(err))
		}
		if provisionPermissionSet == nil || provisionPermissionSet.PermissionSetProvisioningStatus == nil || provisionPermissionSet.PermissionSetProvisioningStatus.RequestId == nil {
			return fmt.Errorf("provision call returned no request id")
		}
		reqID = aws.ToString(provisionPermissionSet.PermissionSetProvisioningStatus.RequestId)
		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 2 * time.Minute
	if err := backoff.Retry(provisionPermissionSetRequest, reconnectBackoff); err != nil {
		return false, []error{err}
	}

	waitBackoff := backoff.NewExponentialBackOff()
	waitBackoff.MaxElapsedTime = maxWait

	describePermissionSetProvisioningStatusRequest := backoff.Retry(func() error {
		describePermissionSetProvisioningStatus, err := r.sso.DescribePermissionSetProvisioningStatus(ctx, &awsSsoAdminClient.DescribePermissionSetProvisioningStatusInput{
			InstanceArn:                     aws.String(state.PermissionSet.InstanceArn.ValueString()),
			ProvisionPermissionSetRequestId: aws.String(reqID),
		})
		if err != nil {
			var ae smithy.APIError
			if errors.As(err, &ae) && (ae.ErrorCode() == "ThrottlingException" || ae.ErrorCode() == "TooManyRequestsException") {
				return err
			}
			return backoff.Permanent(err)
		}
		if describePermissionSetProvisioningStatus == nil || describePermissionSetProvisioningStatus.PermissionSetProvisioningStatus == nil {
			return fmt.Errorf("empty provisioning status for %s", reqID)
		}
		switch describePermissionSetProvisioningStatus.PermissionSetProvisioningStatus.Status {
		case ssoTypes.StatusValuesSucceeded:
			return nil
		case ssoTypes.StatusValuesFailed:
			return backoff.Permanent(fmt.Errorf("provisioning %s failed: %s",
				reqID, aws.ToString(describePermissionSetProvisioningStatus.PermissionSetProvisioningStatus.FailureReason)))
		default:
			return fmt.Errorf("still waiting on provisioning %s", reqID)
		}
	}, waitBackoff)

	if describePermissionSetProvisioningStatusRequest != nil {
		return false, []error{describePermissionSetProvisioningStatusRequest}
	}
	return true, nil
}

// detachCustomerPoliciesFromPermissionSet detaches the specified customer-managed policy
// references from a Permission Set and waits until each (Name, Path) reference disappears.
//
// Parameters
//   - ctx: request context (cancellation/deadline honored by retries)
//   - state: model containing Permission Set identifiers and the target policy names in CombinedPolicesDetail.
//
// Returns
//   - err: Error.
func (r *iamPolicyV2Resource) detachCustomerPoliciesFromPermissionSet(ctx context.Context, state *iamPolicyV2ResourceModel) (unexpectedError []error) {
	customerPolicies := map[string]struct{}{}
	for _, combinedPolicy := range state.CombinedPolicesDetail {
		if !combinedPolicy.PolicyName.IsNull() && !combinedPolicy.PolicyName.IsUnknown() && combinedPolicy.PolicyName.ValueString() != "" {
			customerPolicies[combinedPolicy.PolicyName.ValueString()] = struct{}{}
		}
	}

	// To ensure the policy has been fully detach, keep on polls the `ListCustomerManagedPolicyReferencesInPermissionSet`
	// until the (Name, Path) reference disappears.
	waitDetachCustomerPoliciesFromPermissionSet := func(name, path string, maxWait time.Duration) error {
		if strings.TrimSpace(path) == "" {
			path = "/"
		}
		listCustomerManagedPolicyReferencesInPermissionSetRequest := func() error {
			listCustomerManagedPolicyReferencesInPermissionSet, err := r.sso.ListCustomerManagedPolicyReferencesInPermissionSet(ctx,
				&awsSsoAdminClient.ListCustomerManagedPolicyReferencesInPermissionSetInput{
					InstanceArn:      aws.String(state.PermissionSet.InstanceArn.ValueString()),
					PermissionSetArn: aws.String(state.PermissionSet.PermissionSetArn.ValueString()),
				})
			if err != nil {
				var ae smithy.APIError
				if errors.As(err, &ae) && (ae.ErrorCode() == "NoSuchEntity" || ae.ErrorCode() == "ResourceNotFoundException") {
					return nil
				}
				return err
			}
			for _, reference := range listCustomerManagedPolicyReferencesInPermissionSet.CustomerManagedPolicyReferences {
				referenceName := aws.ToString(reference.Name)
				referencePath := aws.ToString(reference.Path)
				if strings.TrimSpace(referencePath) == "" {
					referencePath = "/"
				}
				if referenceName == name && referencePath == path {
					return fmt.Errorf("policy %s still referenced (path %s)", name, path)
				}
			}
			return nil
		}
		waitBackoff := backoff.NewExponentialBackOff()
		waitBackoff.MaxElapsedTime = maxWait
		return backoff.Retry(listCustomerManagedPolicyReferencesInPermissionSetRequest, backoff.WithContext(waitBackoff, ctx))
	}

	listAndDetachCustomerPoliciesFromPermissionSet := func() error {
		var ae smithy.APIError

		listCustomerManagedPolicyReferencesInPermissionSetRequest, err := r.sso.ListCustomerManagedPolicyReferencesInPermissionSet(ctx,
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

		for _, ref := range listCustomerManagedPolicyReferencesInPermissionSetRequest.CustomerManagedPolicyReferences {
			if ref.Name == nil {
				continue
			}
			referenceName := aws.ToString(ref.Name)
			actualPath := aws.ToString(ref.Path)
			if strings.TrimSpace(actualPath) == "" {
				actualPath = "/"
			}

			if _, ok := customerPolicies[referenceName]; !ok {
				continue
			}

			_, err := r.sso.DetachCustomerManagedPolicyReferenceFromPermissionSet(ctx,
				&awsSsoAdminClient.DetachCustomerManagedPolicyReferenceFromPermissionSetInput{
					InstanceArn:      aws.String(state.PermissionSet.InstanceArn.ValueString()),
					PermissionSetArn: aws.String(state.PermissionSet.PermissionSetArn.ValueString()),
					CustomerManagedPolicyReference: &ssoTypes.CustomerManagedPolicyReference{
						Name: aws.String(referenceName),
						Path: aws.String(actualPath),
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

			// After a successful detach, wait until the reference is actually gone.
			if waitErr := waitDetachCustomerPoliciesFromPermissionSet(referenceName, actualPath, 90*time.Second); waitErr != nil {
				unexpectedError = append(unexpectedError, waitErr)
			}
		}
		return nil
	}

	waitBackoff := backoff.NewExponentialBackOff()
	waitBackoff.MaxElapsedTime = 30 * time.Second
	if err := backoff.Retry(listAndDetachCustomerPoliciesFromPermissionSet, backoff.WithContext(waitBackoff, ctx)); err != nil {
		unexpectedError = append(unexpectedError, err)
	}
	return unexpectedError
}

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

func assigneeTypeOf(assignee *iamPolicyV2ResourceModel) (assigneeType string, assigneeName string) {
	if assignee == nil {
		return "", "(unknown-target)"
	}
	if assignee.Role != nil && !assignee.Role.RoleName.IsNull() && !assignee.Role.RoleName.IsUnknown() && assignee.Role.RoleName.ValueString() != "" {
		return "role", assignee.Role.RoleName.ValueString()
	}
	if assignee.User != nil && !assignee.User.UserName.IsNull() && !assignee.User.UserName.IsUnknown() && assignee.User.UserName.ValueString() != "" {
		return "user", assignee.User.UserName.ValueString()
	}
	if assignee.PermissionSet != nil && !assignee.PermissionSet.PermissionSetName.IsNull() && !assignee.PermissionSet.PermissionSetName.IsUnknown() && assignee.PermissionSet.PermissionSetName.ValueString() != "" {
		return "permissionSet", assignee.PermissionSet.PermissionSetName.ValueString()
	}
	return "", "(unknown-target)"
}

func addReadCombinedDiags(diags *diag.Diagnostics, assigneeName string, notFoundErrs, unexpectedErrs []error) {
	addDiagnostics(
		diags, "error",
		fmt.Sprintf("[API ERROR] Failed to Read Combined Policies for %v: Policy Not Found!", assigneeName),
		notFoundErrs, "",
	)
	addDiagnostics(
		diags, "error",
		fmt.Sprintf("[API ERROR] Failed to Read Combined Policies for %v: Unexpected Error!", assigneeName),
		unexpectedErrs, "",
	)
}
