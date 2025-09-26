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
	"github.com/aws/smithy-go"
	"github.com/cenkalti/backoff"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const (
	// Number of 30 indicates the character length of neccessary policy keyword
	// such as "Version" and "Statement" and some JSON symbols ({}, []).
	permissionSetPolicyKeywordLength = 30
	permissionSetPolicyMaxLength     = 6144
)

var (
	_ resource.Resource              = &iamPermissionSetPolicyResource{}
	_ resource.ResourceWithConfigure = &iamPermissionSetPolicyResource{}
)

func NewIamPermissionSetPolicyResource() resource.Resource {
	return &iamPermissionSetPolicyResource{}
}

type iamPermissionSetPolicyResource struct {
	client *awsIamClient.Client
	sso    *awsSsoAdminClient.Client
}

type iamPermissionSetPolicyResourceModel struct {
	PolicyName             types.String                 `tfsdk:"policy_name"`
	AttachedPolicies       types.List                   `tfsdk:"attached_policies"`
	AttachedPoliciesDetail []*permissionSetPolicyDetail `tfsdk:"attached_policies_detail"`
	CombinedPolicesDetail  []*permissionSetPolicyDetail `tfsdk:"combined_policies_detail"`
	InstanceArn            types.String                 `tfsdk:"instance_arn"`
	PermissionSetArn       types.String                 `tfsdk:"permission_set_arn"`
	PolicyPath             types.String                 `tfsdk:"policy_path"`
}

type permissionSetPolicyDetail struct {
	PolicyName     types.String `tfsdk:"policy_name"`
	PolicyDocument types.String `tfsdk:"policy_document"`
}

func (r *iamPermissionSetPolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_iam_permission_set_policy"
}

func (r *iamPermissionSetPolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provides a IAM Policy resource that manages policy content " +
			"exceeding character limits by splitting it into smaller segments. " +
			"These segments are combined to form a complete policy attached to the permission set. " +
			"However, the policy like `ReadOnlyAccess` that exceed the maximum length " +
			"of a policy, they will be attached directly to the permission set.",
		Attributes: map[string]schema.Attribute{
			"policy_name": schema.StringAttribute{
				Description: "The name of the policy.",
				Required:    true,
			},
			"attached_policies": schema.ListAttribute{
				Description: "The IAM policies.",
				Required:    true,
				ElementType: types.StringType,
			},
			"attached_policies_detail": schema.ListNestedAttribute{
				Description: "A list of policies. Used to compare whether policy has been changed outside of Terraform",
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
				Description: "A list of combined policies.",
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
			"instance_arn": schema.StringAttribute{
				Description: "ARN of the AWS IAM Identity Center (SSO) instance.",
				Required:    true,
			},
			"permission_set_arn": schema.StringAttribute{
				Description: "ARN of the target permission set in IAM Identity Center.",
				Required:    true,
			},
			"policy_path": schema.StringAttribute{
				Description: "Policy path for customer-managed policy references.",
				Optional:    true,
				Computed:    true,
			},
		},
	}
}

func (r *iamPermissionSetPolicyResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	r.client = req.ProviderData.(awsClients).iamClient
	r.sso = req.ProviderData.(awsClients).ssoAdminClient
}

func (r *iamPermissionSetPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan *iamPermissionSetPolicyResourceModel
	if diags := req.Config.Get(ctx, &plan); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	if plan.InstanceArn.IsUnknown() || plan.InstanceArn.IsNull() ||
		plan.PermissionSetArn.IsUnknown() || plan.PermissionSetArn.IsNull() {
		resp.Diagnostics.AddError(
			"Missing required Identity Center fields",
			"instance_arn and permission_set_arn are required.",
		)
		return
	}

	if r.sso == nil {
		resp.Diagnostics.AddError(
			"SSO Admin client not initialized",
			"The SSO Admin client is nil. Ensure the provider constructs ssoadmin.Client and sets it in ProviderData.",
		)
		return
	}

	combined, attached, createErrs := r.createPolicy(ctx, plan)
	addDiagnostics(&resp.Diagnostics, "error", "[API ERROR] Failed to Create the Policy.", createErrs, "")
	if resp.Diagnostics.HasError() {
		return
	}

	state := &iamPermissionSetPolicyResourceModel{
		PolicyName:             plan.PolicyName,
		AttachedPolicies:       plan.AttachedPolicies,
		AttachedPoliciesDetail: attached,
		CombinedPolicesDetail:  combined,
		InstanceArn:            plan.InstanceArn,
		PermissionSetArn:       plan.PermissionSetArn,
		PolicyPath:             plan.PolicyPath, // will be "/" by default if using stringdefault
	}

	nf, errs := r.readCombinedPolicy(ctx, state)
	addDiagnostics(&resp.Diagnostics, "error",
		fmt.Sprintf("[API ERROR] Failed to Read Combined Policies for %v: Policy Not Found!", state.PolicyName),
		nf, "")
	addDiagnostics(&resp.Diagnostics, "error",
		fmt.Sprintf("[API ERROR] Failed to Read Combined Policies for %v: Unexpected Error!", state.PolicyName),
		errs, "")
	if resp.Diagnostics.HasError() {
		return
	}

	attachErrs := r.attachCustomerPoliciesToPermissionSet(ctx, state)
	addDiagnostics(&resp.Diagnostics, "error",
		"[API ERROR] Failed to attach customer-managed policies to Permission Set.",
		attachErrs, "")
	if resp.Diagnostics.HasError() {
		return
	}

	provErrs := r.provisionPermissionSetAll(ctx, state)
	addDiagnostics(&resp.Diagnostics, "error",
		"[API ERROR] Failed to provision Permission Set.", provErrs, "")
	if resp.Diagnostics.HasError() {
		return
	}

	if diags := resp.State.Set(ctx, &state); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
}

func (r *iamPermissionSetPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state *iamPermissionSetPolicyResourceModel
	getStateDiags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(getStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if state.PolicyPath.IsNull() || state.PolicyPath.IsUnknown() || state.PolicyPath.ValueString() == "" {
		state.PolicyPath = types.StringValue("/")
	}

	// This state will be using to compare with the current state.
	var oriState *iamPermissionSetPolicyResourceModel
	getOriStateDiags := req.State.Get(ctx, &oriState)
	resp.Diagnostics.Append(getOriStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	readCombinedPolicyNotExistErr, readCombinedPolicyErr := r.readCombinedPolicy(ctx, state)
	addDiagnostics(
		&resp.Diagnostics,
		"warning",
		fmt.Sprintf("[API WARNING] Failed to Read Combined Policies for %v: Policy Not Found!", state.PolicyName),
		readCombinedPolicyNotExistErr,
		"The combined policies may be deleted due to human mistake or API error, will trigger update to recreate the combined policy:",
	)
	addDiagnostics(
		&resp.Diagnostics,
		"error",
		fmt.Sprintf("[API ERROR] Failed to Read Combined Policies for %v: Unexpected Error!", state.PolicyName),
		readCombinedPolicyErr,
		"",
	)

	// Set state so that Terraform will trigger update if there are changes in state.
	setStateDiags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.WarningsCount() > 0 || resp.Diagnostics.HasError() {
		return
	}

	// If the attached policy not found, it should return warning instead of error
	// because there is no ways to get plan configuration in Read() function to
	// indicate had removed the non existed policies from the input.
	readAttachedPolicyNotExistErr, readAttachedPolicyErr := r.readAttachedPolicy(ctx, state)
	addDiagnostics(
		&resp.Diagnostics,
		"warning",
		fmt.Sprintf("[API WARNING] Failed to Read Attached Policies for %v: Policy Not Found!", state.PolicyName),
		readAttachedPolicyNotExistErr,
		"The policy that will be used to combine policies had been removed on AWS, next apply with update will prompt error:",
	)
	addDiagnostics(
		&resp.Diagnostics,
		"error",
		fmt.Sprintf("[API ERROR] Failed to Read Attached Policies for %v: Unexpected Error!", state.PolicyName),
		readAttachedPolicyErr,
		"",
	)

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
		fmt.Sprintf("[API WARNING] Policy Drift Detected for %v.", state.PolicyName),
		[]error{compareAttachedPoliciesErr},
		"This resource will be updated in the next terraform apply.",
	)

	setStateDiags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *iamPermissionSetPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state *iamPermissionSetPolicyResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.PolicyPath.IsNull() || plan.PolicyPath.IsUnknown() || plan.PolicyPath.ValueString() == "" {
		plan.PolicyPath = types.StringValue("/")
	}

	// Validate/guard SSO client before detach/attach/provision
	if r.sso == nil {
		resp.Diagnostics.AddError("SSO Admin client not initialized",
			"The SSO Admin client is nil. Ensure the provider constructs ssoadmin.Client and sets it in ProviderData.")
		return
	}

	// 1) Refresh attached policies exist (your existing check)
	readAttachedPolicyNotExistErr, readAttachedPolicyErr := r.readAttachedPolicy(ctx, plan)
	addDiagnostics(&resp.Diagnostics, "error",
		fmt.Sprintf("[API ERROR] Failed to Read Attached Policies for %v: Policy Not Found!", state.PolicyName),
		readAttachedPolicyNotExistErr,
		"The policy that will be used to combine policies had been removed on AWS:",
	)
	addDiagnostics(&resp.Diagnostics, "error",
		fmt.Sprintf("[API ERROR] Failed to Read Attached Policies for %v: Unexpected Error!", state.PolicyName),
		readAttachedPolicyErr, "")
	if resp.Diagnostics.HasError() {
		return
	}

	// 2) Detach from Permission Set (idempotent) + provision
	detachErrs := r.detachCustomerPoliciesFromPermissionSet(ctx, state)
	addDiagnostics(&resp.Diagnostics, "error",
		"[API ERROR] Failed to detach customer-managed policies from Permission Set.",
		detachErrs, "")
	if resp.Diagnostics.HasError() {
		return
	}

	provErrs := r.provisionPermissionSetAll(ctx, state)
	addDiagnostics(&resp.Diagnostics, "error",
		"[API ERROR] Failed to provision Permission Set after detach.", provErrs, "")
	if resp.Diagnostics.HasError() {
		return
	}

	// 3) Remove old IAM policies
	removePolicyErr := r.removePolicy(ctx, state)
	addDiagnostics(&resp.Diagnostics, "error",
		fmt.Sprintf("[API ERROR] Failed to Remove Policies for %v: Unexpected Error!", state.PolicyName),
		removePolicyErr, "")
	if resp.Diagnostics.HasError() {
		return
	}

	state.CombinedPolicesDetail = nil
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// 4) Create new combined IAM policies
	combinedPolicies, attachedPolicies, errs := r.createPolicy(ctx, plan)
	addDiagnostics(&resp.Diagnostics, "error", "[API ERROR] Failed to Create the Policy.", errs, "")
	if resp.Diagnostics.HasError() {
		return
	}

	state.PolicyName = plan.PolicyName
	state.AttachedPolicies = plan.AttachedPolicies
	state.AttachedPoliciesDetail = attachedPolicies
	state.CombinedPolicesDetail = combinedPolicies
	state.PolicyPath = plan.PolicyPath // persist default if needed

	// 5) Read back combined (your behavior)
	readCombinedPolicyNotExistErr, readCombinedPolicyErr := r.readCombinedPolicy(ctx, state)
	addDiagnostics(&resp.Diagnostics, "error",
		fmt.Sprintf("[API ERROR] Failed to Read Combined Policies for %v: Policy Not Found!", state.PolicyName),
		readCombinedPolicyNotExistErr, "")
	addDiagnostics(&resp.Diagnostics, "error",
		fmt.Sprintf("[API ERROR] Failed to Read Combined Policies for %v: Unexpected Error!", state.PolicyName),
		readCombinedPolicyErr, "")
	if resp.Diagnostics.HasError() {
		return
	}

	// 6) Reattach to Permission Set + provision
	attachErrs := r.attachCustomerPoliciesToPermissionSet(ctx, state)
	addDiagnostics(&resp.Diagnostics, "error",
		"[API ERROR] Failed to attach customer-managed policies to Permission Set.",
		attachErrs, "")
	if resp.Diagnostics.HasError() {
		return
	}

	provErrs = r.provisionPermissionSetAll(ctx, state)
	addDiagnostics(&resp.Diagnostics, "error",
		"[API ERROR] Failed to provision Permission Set after attach.", provErrs, "")
	if resp.Diagnostics.HasError() {
		return
	}

	// 7) Save state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *iamPermissionSetPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state *iamPermissionSetPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Default policy path in memory for detach
	if state.PolicyPath.IsNull() || state.PolicyPath.IsUnknown() || state.PolicyPath.ValueString() == "" {
		state.PolicyPath = types.StringValue("/")
	}

	// Detach from Permission Set (best effort) + provision
	if r.sso != nil &&
		!state.InstanceArn.IsNull() && !state.InstanceArn.IsUnknown() &&
		!state.PermissionSetArn.IsNull() && !state.PermissionSetArn.IsUnknown() {

		detachErrs := r.detachCustomerPoliciesFromPermissionSet(ctx, state)
		addDiagnostics(&resp.Diagnostics, "error",
			"[API ERROR] Failed to detach customer-managed policies from Permission Set.",
			detachErrs, "")
		if resp.Diagnostics.HasError() {
			return
		}

		provErrs := r.provisionPermissionSetAll(ctx, state)
		addDiagnostics(&resp.Diagnostics, "error",
			"[API ERROR] Failed to provision Permission Set after detach.", provErrs, "")
		if resp.Diagnostics.HasError() {
			return
		}
	}

	// Remove IAM policies
	removePolicyUnexpectedErr := r.removePolicy(ctx, state)
	addDiagnostics(&resp.Diagnostics, "error",
		fmt.Sprintf("[API ERROR] Failed to Remove Policies for %v: Unexpected Error!", state.PolicyName),
		removePolicyUnexpectedErr, "")
}

func (r *iamPermissionSetPolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	policyDetailsState := []*permissionSetPolicyDetail{}
	getPolicyDocumentResponse := &awsIamClient.GetPolicyVersionOutput{}
	policyNames := strings.Split(req.ID, ",")

	var err error
	getPolicy := func() error {
		for _, policyName := range policyNames {
			policyName = strings.ReplaceAll(policyName, " ", "")

			// Retrieves the policy document for the policy
			policyArn, policyVersionId, _ := r.getPolicyArn(ctx, policyName)

			getPolicyDocumentResponse, err = r.client.GetPolicyVersion(ctx, &awsIamClient.GetPolicyVersionInput{
				PolicyArn: aws.String(policyArn),
				VersionId: aws.String(policyVersionId),
			})
			if err != nil {
				handleAPIError(err)
			}

			if getPolicyDocumentResponse.PolicyVersion != nil {
				policyDocument, err := url.QueryUnescape(*getPolicyDocumentResponse.PolicyVersion.Document)
				if err != nil {
					resp.Diagnostics.AddError(
						"[API ERROR] Failed to Convert the Policy Document.",
						err.Error(),
					)
				}

				permissionSetPolicyDetail := permissionSetPolicyDetail{
					PolicyName:     types.StringValue(policyName),
					PolicyDocument: types.StringValue(policyDocument),
				}
				policyDetailsState = append(policyDetailsState, &permissionSetPolicyDetail)
			}
		}
		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second
	err = backoff.Retry(getPolicy, reconnectBackoff)
	if err != nil {
		return
	}

	var policyList []permissionSetPolicyDetail
	for _, policy := range policyDetailsState {
		policies := permissionSetPolicyDetail{
			PolicyName:     types.StringValue(policy.PolicyName.ValueString()),
			PolicyDocument: types.StringValue(policy.PolicyDocument.ValueString()),
		}

		policyList = append(policyList, policies)
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("policies"), policyList)...)

	if !resp.Diagnostics.HasError() {
		resp.Diagnostics.AddWarning(
			"Unable to Set the attached_policies Attribute",
			"After running terraform import, Terraform will not automatically set the attached_policies attributes."+
				"To ensure that all attributes defined in the Terraform configuration are set, you need to run terraform apply."+
				"This command will apply the changes and set the desired attributes according to your configuration.",
		)
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
func (r *iamPermissionSetPolicyResource) createPolicy(ctx context.Context, plan *iamPermissionSetPolicyResourceModel) (combinedPoliciesDetail []*permissionSetPolicyDetail, attachedPoliciesDetail []*permissionSetPolicyDetail, errList []error) {
	var policies []string
	plan.AttachedPolicies.ElementsAs(ctx, &policies, false)
	combinedPolicyDocuments, excludedPolicies, attachedPoliciesDetail, errList := r.combinePolicyDocument(ctx, policies)
	if errList != nil {
		return nil, nil, errList
	}

	createPolicy := func() error {
		for i, policy := range combinedPolicyDocuments {
			policyName := fmt.Sprintf("%s-%d", plan.PolicyName.ValueString(), i+1)

			createPolicyRequest := &awsIamClient.CreatePolicyInput{
				PolicyName:     aws.String(policyName),
				PolicyDocument: aws.String(policy),
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
		policyName := fmt.Sprintf("%s-%d", plan.PolicyName.ValueString(), i+1)

		combinedPoliciesDetail = append(combinedPoliciesDetail, &permissionSetPolicyDetail{
			PolicyName:     types.StringValue(policyName),
			PolicyDocument: types.StringValue(policies),
		})
	}

	combinedPoliciesDetail = append(combinedPoliciesDetail, excludedPolicies...)

	return combinedPoliciesDetail, attachedPoliciesDetail, nil
}

// combinePolicyDocument combines multiple IAM policies into one or more
// policy documents, while respecting AWS size limitations.
//
// Parameters:
//   - ctx: Context.
//   - attachedPolicies: List of policy names to be combined.
//
// Returns:
//   - combinedPolicyDocument: A slice of JSON policy documents. If the total
//     combined statements exceed the 6144-character limit, the function will
//     split them into multiple valid policy documents.
//   - excludedPolicies: Policies skipped from combination because a single
//     policy document exceeded the maximum size limit.
//   - attachedPoliciesDetail: Details of the fetched policies, recorded for
//     storing in Terraform state.
//   - errList: List of errors that occurred during processing. Returns nil if
//     no errors.
func (r *iamPermissionSetPolicyResource) combinePolicyDocument(ctx context.Context, attachedPolicies []string) (combinedPolicyDocument []string, excludedPolicies []*permissionSetPolicyDetail, attachedPoliciesDetail []*permissionSetPolicyDetail, errList []error) {
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
		if len(noWhitespace) > permissionSetPolicyMaxLength {
			excludedPolicies = append(excludedPolicies, &permissionSetPolicyDetail{
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
		// of 'permissionSetPolicyKeywordLength' to simulate the total length of completed
		// policy to check whether it is already execeeded the max character
		// length of 6144.
		if (currentLength + permissionSetPolicyKeywordLength) > permissionSetPolicyMaxLength {
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
func (r *iamPermissionSetPolicyResource) readCombinedPolicy(ctx context.Context, state *iamPermissionSetPolicyResourceModel) (notExistErrs, unexpectedErrs []error) {
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
func (r *iamPermissionSetPolicyResource) readAttachedPolicy(ctx context.Context, state *iamPermissionSetPolicyResourceModel) (notExistErrs, unexpectedErrs []error) {
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
//   - policyTypes: List of IAM policy types to retrieve.
//
// Returns:
//   - policiesDetail: List of retrieved policies detail.
//   - notExistError: List of allowed not exist errors to be used as warning messages instead, return empty list if no errors.
//   - unexpectedError: List of unexpected errors to be used as normal error messages, return empty list if no errors.
func (r *iamPermissionSetPolicyResource) fetchPolicies(ctx context.Context, policiesName []string) (policiesDetail []*permissionSetPolicyDetail, notExistError, unexpectedError []error) {
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
			policiesDetail = append(policiesDetail, &permissionSetPolicyDetail{
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
func (r *iamPermissionSetPolicyResource) checkPoliciesDrift(newState, oriState *iamPermissionSetPolicyResourceModel) error {
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

// removePolicy deletes the managed IAM policies recorded in state, along with
// any non-default policy versions.
//
// Parameters:
//   - ctx:   Context.
//   - state: The recorded state containing combined policy details.
func (r *iamPermissionSetPolicyResource) removePolicy(ctx context.Context, state *iamPermissionSetPolicyResourceModel) (unexpectedError []error) {
	var ae smithy.APIError
	var listPolicyVersionsResponse *awsIamClient.ListPolicyVersionsOutput

	removePolicy := func() error {
		for _, combinedPolicy := range state.CombinedPolicesDetail {
			policyArn, _, err := r.getPolicyArn(ctx, combinedPolicy.PolicyName.ValueString())

			if err != nil {
				unexpectedError = append(unexpectedError, err)
				continue
			}

			listPolicyVersionsRequest := &awsIamClient.ListPolicyVersionsInput{
				PolicyArn: aws.String(policyArn),
			}

			deletePolicyRequest := &awsIamClient.DeletePolicyInput{
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

func (r *iamPermissionSetPolicyResource) getPolicyArn(ctx context.Context, policyName string) (policyArn string, policyVersionId string, err error) {
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

func (r *iamPermissionSetPolicyResource) attachCustomerPoliciesToPermissionSet(ctx context.Context, state *iamPermissionSetPolicyResourceModel) (unexpectedError []error) {
	if r.sso == nil {
		return []error{fmt.Errorf("SSO Admin client is nil; ensure provider configured ssoadmin.Client")}
	}
	if state.InstanceArn.IsNull() || state.InstanceArn.IsUnknown() ||
		state.PermissionSetArn.IsNull() || state.PermissionSetArn.IsUnknown() {
		return []error{fmt.Errorf("instance_arn and permission_set_arn are required")}
	}
	if len(state.CombinedPolicesDetail) == 0 {
		// nothing to attach; treat as success
		return nil
	}

	attachFn := func() error {
		path := state.PolicyPath.ValueString()
		if path == "" {
			path = "/"
		}

		var ae smithy.APIError

		for _, combinedPolicy := range state.CombinedPolicesDetail {
			input := &awsSsoAdminClient.AttachCustomerManagedPolicyReferenceToPermissionSetInput{
				InstanceArn:      aws.String(state.InstanceArn.ValueString()),
				PermissionSetArn: aws.String(state.PermissionSetArn.ValueString()),
				CustomerManagedPolicyReference: &ssoTypes.CustomerManagedPolicyReference{
					Name: aws.String(combinedPolicy.PolicyName.ValueString()),
					Path: aws.String(path),
				},
			}

			_, err := r.sso.AttachCustomerManagedPolicyReferenceToPermissionSet(ctx, input)
			if err == nil {
				continue
			}

			// Classify the error
			if errors.As(err, &ae) {
				switch ae.ErrorCode() {
				case "ConflictException":
					// Already attached → idempotent success; continue.
					continue
				case "ThrottlingException", "TooManyRequestsException", "ServiceQuotaExceededException":
					// Retryable → bubble up to backoff
					return err
				case "AccessDeniedException", "ValidationException", "ResourceNotFoundException":
					// Non-retryable but continue with others; record it.
					unexpectedError = append(unexpectedError, handleAPIError(err))
					continue
				default:
					// Unknown; let backoff retry once (could be transient)
					return handleAPIError(err)
				}
			}

			// Non-API error (network ctx cancel, etc.). Let backoff retry.
			return handleAPIError(err)
		}

		// Do not return aggregated unexpectedError here; we only use return to trigger backoff retries.
		return nil
	}

	back := backoff.NewExponentialBackOff()
	back.MaxElapsedTime = 30 * time.Second
	if err := backoff.Retry(attachFn, back); err != nil {
		// final retry failed → include it
		unexpectedError = append(unexpectedError, err)
	}

	return unexpectedError
}

func (r *iamPermissionSetPolicyResource) provisionPermissionSetAll(ctx context.Context, state *iamPermissionSetPolicyResourceModel) (unexpectedError []error) {
	if r.sso == nil {
		return []error{fmt.Errorf("SSO Admin client is nil; ensure provider configured ssoadmin.Client")}
	}
	prov := func() error {
		_, err := r.sso.ProvisionPermissionSet(ctx, &awsSsoAdminClient.ProvisionPermissionSetInput{
			InstanceArn:      aws.String(state.InstanceArn.ValueString()),
			PermissionSetArn: aws.String(state.PermissionSetArn.ValueString()),
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

func (r *iamPermissionSetPolicyResource) detachCustomerPoliciesFromPermissionSet(
	ctx context.Context,
	state *iamPermissionSetPolicyResourceModel,
) (unexpectedError []error) {

	if r.sso == nil {
		return []error{fmt.Errorf("SSO Admin client is nil; ensure provider configured ssoadmin.Client")}
	}
	if state.InstanceArn.IsNull() || state.InstanceArn.IsUnknown() ||
		state.PermissionSetArn.IsNull() || state.PermissionSetArn.IsUnknown() {
		return []error{fmt.Errorf("instance_arn and permission_set_arn are required to detach policies")}
	}

	// Build a quick set of names we created (policy_name-1, policy_name-2, ...)
	want := map[string]struct{}{}
	for _, cp := range state.CombinedPolicesDetail {
		want[cp.PolicyName.ValueString()] = struct{}{}
	}

	listAndDetach := func() error {
		path := state.PolicyPath.ValueString()
		if path == "" {
			path = "/"
		}

		// List current customer-managed refs on the permission set
		var ae smithy.APIError
		out, err := r.sso.ListCustomerManagedPolicyReferencesInPermissionSet(ctx,
			&awsSsoAdminClient.ListCustomerManagedPolicyReferencesInPermissionSetInput{
				InstanceArn:      aws.String(state.InstanceArn.ValueString()),
				PermissionSetArn: aws.String(state.PermissionSetArn.ValueString()),
			})
		if err != nil {
			if errors.As(err, &ae) && (ae.ErrorCode() == "ThrottlingException" || ae.ErrorCode() == "TooManyRequestsException") {
				return err // retry
			}
			return handleAPIError(err)
		}

		for _, ref := range out.CustomerManagedPolicyReferences {
			if ref.Name == nil {
				continue
			}
			name := *ref.Name
			// only detach what we attached
			if _, ok := want[name]; !ok {
				continue
			}
			_, err := r.sso.DetachCustomerManagedPolicyReferenceFromPermissionSet(ctx,
				&awsSsoAdminClient.DetachCustomerManagedPolicyReferenceFromPermissionSetInput{
					InstanceArn:      aws.String(state.InstanceArn.ValueString()),
					PermissionSetArn: aws.String(state.PermissionSetArn.ValueString()),
					CustomerManagedPolicyReference: &ssoTypes.CustomerManagedPolicyReference{
						Name: aws.String(name),
						Path: aws.String(path),
					},
				})
			if err != nil {
				if errors.As(err, &ae) {
					switch ae.ErrorCode() {
					case "ResourceNotFoundException", "ConflictException":
						// already detached / transient attach change; treat as idempotent
						continue
					case "ThrottlingException", "TooManyRequestsException":
						return err // retry
					}
				}
				// keep going for others, but record error
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
