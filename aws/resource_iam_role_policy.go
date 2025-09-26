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
	rolePolicyKeywordLength = 30
	rolePolicyMaxLength     = 6144
)

var (
	_ resource.Resource              = &iamRolePolicyResource{}
	_ resource.ResourceWithConfigure = &iamRolePolicyResource{}
)

func NewIamRolePolicyResource() resource.Resource {
	return &iamRolePolicyResource{}
}

type iamRolePolicyResource struct {
	client *awsIamClient.Client
}

type iamRolePolicyResourceModel struct {
	RoleName               types.String        `tfsdk:"role_name"`
	AttachedPolicies       types.List          `tfsdk:"attached_policies"`
	AttachedPoliciesDetail []*rolePolicyDetail `tfsdk:"attached_policies_detail"`
	CombinedPolicesDetail  []*rolePolicyDetail `tfsdk:"combined_policies_detail"`
}

type rolePolicyDetail struct {
	PolicyName     types.String `tfsdk:"policy_name"`
	PolicyDocument types.String `tfsdk:"policy_document"`
}

func (r *iamRolePolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_iam_role_policy"
}

func (r *iamRolePolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provides a IAM Policy resource that manages policy content " +
			"exceeding character limits by splitting it into smaller segments. " +
			"These segments are combined to form a complete policy attached to the role. " +
			"However, the policy like `ReadOnlyAccess` that exceed the maximum length " +
			"of a policy, they will be attached directly to the role.",
		Attributes: map[string]schema.Attribute{
			"role_name": schema.StringAttribute{
				Description: "The role that attached to the policy.",
				Required:    true,
			},
			"attached_policies": schema.ListAttribute{
				Description: "The IAM policies to attach to the role.",
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
				Description: "A list of combined policies that are attached to roles.",
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
	}
}

func (r *iamRolePolicyResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(awsClients).iamClient
}

func (r *iamRolePolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan *iamRolePolicyResourceModel
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

	state := &iamRolePolicyResourceModel{}
	state.RoleName = plan.RoleName
	state.AttachedPolicies = plan.AttachedPolicies
	state.AttachedPoliciesDetail = attachedPolicies
	state.CombinedPolicesDetail = combinedPolicies

	attachPolicyToRoleErr := r.attachPolicyToRole(ctx, state)
	addDiagnostics(
		&resp.Diagnostics,
		"error",
		"[API ERROR] Failed to Attach Policy to Role.",
		attachPolicyToRoleErr,
		"",
	)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create policy are not expected to have not found warning.
	readCombinedPolicyNotExistErr, readCombinedPolicyErr := r.readCombinedPolicy(ctx, state)
	addDiagnostics(
		&resp.Diagnostics,
		"error",
		fmt.Sprintf("[API ERROR] Failed to Read Combined Policies for %v: Policy Not Found!", state.RoleName),
		readCombinedPolicyNotExistErr,
		"",
	)
	addDiagnostics(
		&resp.Diagnostics,
		"error",
		fmt.Sprintf("[API ERROR] Failed to Read Combined Policies for %v: Unexpected Error!", state.RoleName),
		readCombinedPolicyErr,
		"",
	)
	if resp.Diagnostics.HasError() {
		return
	}

	setStateDiags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *iamRolePolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state *iamRolePolicyResourceModel
	getStateDiags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(getStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// This state will be using to compare with the current state.
	var oriState *iamRolePolicyResourceModel
	getOriStateDiags := req.State.Get(ctx, &oriState)
	resp.Diagnostics.Append(getOriStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	readCombinedPolicyNotExistErr, readCombinedPolicyErr := r.readCombinedPolicy(ctx, state)
	addDiagnostics(
		&resp.Diagnostics,
		"warning",
		fmt.Sprintf("[API WARNING] Failed to Read Combined Policies for %v: Policy Not Found!", state.RoleName),
		readCombinedPolicyNotExistErr,
		"The combined policies may be deleted due to human mistake or API error, will trigger update to recreate the combined policy:",
	)
	addDiagnostics(
		&resp.Diagnostics,
		"error",
		fmt.Sprintf("[API ERROR] Failed to Read Combined Policies for %v: Unexpected Error!", state.RoleName),
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
	// indicate role had removed the non existed policies from the input.
	readAttachedPolicyNotExistErr, readAttachedPolicyErr := r.readAttachedPolicy(ctx, state)
	addDiagnostics(
		&resp.Diagnostics,
		"warning",
		fmt.Sprintf("[API WARNING] Failed to Read Attached Policies for %v: Policy Not Found!", state.RoleName),
		readAttachedPolicyNotExistErr,
		"The policy that will be used to combine policies had been removed on AWS, next apply with update will prompt error:",
	)
	addDiagnostics(
		&resp.Diagnostics,
		"error",
		fmt.Sprintf("[API ERROR] Failed to Read Attached Policies for %v: Unexpected Error!", state.RoleName),
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
		fmt.Sprintf("[API WARNING] Policy Drift Detected for %v.", state.RoleName),
		[]error{compareAttachedPoliciesErr},
		"This resource will be updated in the next terraform apply.",
	)

	setStateDiags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *iamRolePolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state *iamRolePolicyResourceModel
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

	readAttachedPolicyNotExistErr, readAttachedPolicyErr := r.readAttachedPolicy(ctx, plan)
	addDiagnostics(
		&resp.Diagnostics,
		"error",
		fmt.Sprintf("[API ERROR] Failed to Read Attached Policies for %v: Policy Not Found!", state.RoleName),
		readAttachedPolicyNotExistErr,
		"The policy that will be used to combine policies had been removed on AWS:",
	)
	addDiagnostics(
		&resp.Diagnostics,
		"error",
		fmt.Sprintf("[API ERROR] Failed to Read Attached Policies for %v: Unexpected Error!", state.RoleName),
		readAttachedPolicyErr,
		"",
	)
	if resp.Diagnostics.HasError() {
		return
	}

	removePolicyErr := r.removePolicy(ctx, state)
	addDiagnostics(
		&resp.Diagnostics,
		"error",
		fmt.Sprintf("[API ERROR] Failed to Remove Policies for %v: Unexpected Error!", state.RoleName),
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

	state.RoleName = plan.RoleName
	state.AttachedPolicies = plan.AttachedPolicies
	state.AttachedPoliciesDetail = attachedPolicies
	state.CombinedPolicesDetail = combinedPolicies

	attachPolicyToRoleErr := r.attachPolicyToRole(ctx, state)
	addDiagnostics(
		&resp.Diagnostics,
		"error",
		"[API ERROR] Failed to Attach Policy to Role.",
		attachPolicyToRoleErr,
		"",
	)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create policy are not expected to have not found warning.
	readCombinedPolicyNotExistErr, readCombinedPolicyErr := r.readCombinedPolicy(ctx, state)
	addDiagnostics(
		&resp.Diagnostics,
		"error",
		fmt.Sprintf("[API ERROR] Failed to Read Combined Policies for %v: Policy Not Found!", state.RoleName),
		readCombinedPolicyNotExistErr,
		"",
	)
	addDiagnostics(
		&resp.Diagnostics,
		"error",
		fmt.Sprintf("[API ERROR] Failed to Read Combined Policies for %v: Unexpected Error!", state.RoleName),
		readCombinedPolicyErr,
		"",
	)
	if resp.Diagnostics.HasError() {
		return
	}

	setStateDiags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *iamRolePolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state *iamRolePolicyResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	removePolicyUnexpectedErr := r.removePolicy(ctx, state)
	addDiagnostics(
		&resp.Diagnostics,
		"error",
		fmt.Sprintf("[API ERROR] Failed to Remove Policies for %v: Unexpected Error!", state.RoleName),
		removePolicyUnexpectedErr,
		"",
	)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *iamRolePolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	policyDetailsState := []*rolePolicyDetail{}
	getPolicyDocumentResponse := &awsIamClient.GetPolicyVersionOutput{}
	policyNames := strings.Split(req.ID, ",")
	var roleName string

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

			// Retrieves the name of the role attached to the policy.
			getPolicyEntities, err := r.client.ListEntitiesForPolicy(ctx, &awsIamClient.ListEntitiesForPolicyInput{
				PolicyArn: aws.String(policyArn),
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

				rolePolicyDetail := rolePolicyDetail{
					PolicyName:     types.StringValue(policyName),
					PolicyDocument: types.StringValue(policyDocument),
				}
				policyDetailsState = append(policyDetailsState, &rolePolicyDetail)
			}

			if getPolicyEntities.PolicyRoles != nil {
				for _, role := range getPolicyEntities.PolicyRoles {
					roleName = *role.RoleName
				}
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

	var policyList []rolePolicyDetail
	for _, policy := range policyDetailsState {
		policies := rolePolicyDetail{
			PolicyName:     types.StringValue(policy.PolicyName.ValueString()),
			PolicyDocument: types.StringValue(policy.PolicyDocument.ValueString()),
		}

		policyList = append(policyList, policies)
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("role_name"), roleName)...)
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
func (r *iamRolePolicyResource) createPolicy(ctx context.Context, plan *iamRolePolicyResourceModel) (combinedPoliciesDetail []*rolePolicyDetail, attachedPoliciesDetail []*rolePolicyDetail, errList []error) {
	var policies []string
	plan.AttachedPolicies.ElementsAs(ctx, &policies, false)
	combinedPolicyDocuments, excludedPolicies, attachedPoliciesDetail, errList := r.combinePolicyDocument(ctx, policies)
	if errList != nil {
		return nil, nil, errList
	}

	createPolicy := func() error {
		for i, policy := range combinedPolicyDocuments {
			policyName := fmt.Sprintf("%s-%d", plan.RoleName.ValueString(), i+1)

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
		policyName := fmt.Sprintf("%s-%d", plan.RoleName.ValueString(), i+1)

		combinedPoliciesDetail = append(combinedPoliciesDetail, &rolePolicyDetail{
			PolicyName:     types.StringValue(policyName),
			PolicyDocument: types.StringValue(policies),
		})
	}

	// These policies will be attached directly to the role since splitting the
	// policy "statement" will be hitting the limitation of "maximum number of
	// attached policies" easily.
	combinedPoliciesDetail = append(combinedPoliciesDetail, excludedPolicies...)

	return combinedPoliciesDetail, attachedPoliciesDetail, nil
}

// combinePolicyDocument combine the policy with custom logic.
//
// Parameters:
//   - ctx: Context.
//   - attachedPolicies: List of role attached policies to be combined.
//
// Returns:
//   - combinedPolicyDocument: The completed policy document after combining attached policies.
//   - excludedPolicies: If the target policy exceeds maximum length, then do not combine the policy and return as excludedPolicies.
//   - attachedPoliciesDetail: The attached policies detail to be recorded in state file.
//   - errList: List of errors, return nil if no errors.
func (r *iamRolePolicyResource) combinePolicyDocument(ctx context.Context, attachedPolicies []string) (combinedPolicyDocument []string, excludedPolicies []*rolePolicyDetail, attachedPoliciesDetail []*rolePolicyDetail, errList []error) {
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
		if len(noWhitespace) > rolePolicyMaxLength {
			excludedPolicies = append(excludedPolicies, &rolePolicyDetail{
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
		// of 'rolePolicyKeywordLength' to simulate the total length of completed
		// policy to check whether it is already execeeded the max character
		// length of 6144.
		if (currentLength + rolePolicyKeywordLength) > rolePolicyMaxLength {
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
func (r *iamRolePolicyResource) readCombinedPolicy(ctx context.Context, state *iamRolePolicyResourceModel) (notExistErrs, unexpectedErrs []error) {
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
func (r *iamRolePolicyResource) readAttachedPolicy(ctx context.Context, state *iamRolePolicyResourceModel) (notExistErrs, unexpectedErrs []error) {
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
func (r *iamRolePolicyResource) fetchPolicies(ctx context.Context, policiesName []string) (policiesDetail []*rolePolicyDetail, notExistError, unexpectedError []error) {
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
			policiesDetail = append(policiesDetail, &rolePolicyDetail{
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
func (r *iamRolePolicyResource) checkPoliciesDrift(newState, oriState *iamRolePolicyResourceModel) error {
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

// removePolicy will detach and delete the combined policies from role.
//
// Parameters:
//   - state: The recorded state configurations.
func (r *iamRolePolicyResource) removePolicy(ctx context.Context, state *iamRolePolicyResourceModel) (unexpectedError []error) {
	var ae smithy.APIError
	var listPolicyVersionsResponse *awsIamClient.ListPolicyVersionsOutput

	removePolicy := func() error {
		for _, combinedPolicy := range state.CombinedPolicesDetail {
			policyArn, _, err := r.getPolicyArn(ctx, combinedPolicy.PolicyName.ValueString())

			if err != nil {
				unexpectedError = append(unexpectedError, err)
				continue
			}

			detachPolicyFromRoleRequest := &awsIamClient.DetachRolePolicyInput{
				PolicyArn: aws.String(policyArn),
				RoleName:  aws.String(state.RoleName.ValueString()),
			}

			listPolicyVersionsRequest := &awsIamClient.ListPolicyVersionsInput{
				PolicyArn: aws.String(policyArn),
			}

			deletePolicyRequest := &awsIamClient.DeletePolicyInput{
				PolicyArn: aws.String(policyArn),
			}

			if _, err = r.client.DetachRolePolicy(ctx, detachPolicyFromRoleRequest); err != nil {
				// Ignore error where the policy is not attached
				// to the role as it is intented to detach the
				// policy from role.
				if errors.As(err, &ae) && ae.ErrorCode() != "NoSuchEntity" {
					return handleAPIError(err)
				}
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

// attachPolicyToRole attach the IAM policy to role through AWS SDK.
//
// Parameters:
//   - state: The recorded state configurations.
//
// Returns:
//   - err: Error.
func (r *iamRolePolicyResource) attachPolicyToRole(ctx context.Context, state *iamRolePolicyResourceModel) (unexpectedError []error) {
	attachPolicyToRole := func() error {
		for _, combinedPolicy := range state.CombinedPolicesDetail {
			policyArn, _, err := r.getPolicyArn(ctx, combinedPolicy.PolicyName.ValueString())

			if err != nil {
				unexpectedError = append(unexpectedError, err)
				continue
			}

			attachPolicyToRoleRequest := &awsIamClient.AttachRolePolicyInput{
				PolicyArn: aws.String(policyArn),
				RoleName:  aws.String(state.RoleName.ValueString()),
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

func (r *iamRolePolicyResource) getPolicyArn(ctx context.Context, policyName string) (policyArn string, policyVersionId string, err error) {
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
