package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	awsIamClient "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/smithy-go"
	"github.com/cenkalti/backoff"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const maxLength = 6144

var (
	_ resource.Resource              = &iamPolicyResource{}
	_ resource.ResourceWithConfigure = &iamPolicyResource{}
)

func NewIamPolicyResource() resource.Resource {
	return &iamPolicyResource{}
}

type iamPolicyResource struct {
	client *awsIamClient.Client
}

type iamPolicyResourceModel struct {
	AttachedPolicies       types.List      `tfsdk:"attached_policies"`
	Policies               []*policyDetail `tfsdk:"policies"` // TODO: remove when 'Policies' is no longer used.
	CombinedPolices        []*policyDetail `tfsdk:"combined_policies"`
	AttachedPoliciesDetail []*policyDetail `tfsdk:"attached_policies_detail"`
	UserName               types.String    `tfsdk:"user_name"`
}

type policyDetail struct {
	PolicyName     types.String `tfsdk:"policy_name"`
	PolicyDocument types.String `tfsdk:"policy_document"`
}

func (r *iamPolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_iam_policy"
}

func (r *iamPolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provides a RAM Policy resource that manages policy content " +
			"exceeding character limits by splitting it into smaller segments. " +
			"These segments are combined to form a complete policy attached to the user. " +
			"However, the policy like `ReadOnlyAccess` that exceed the maximum length " +
			"of a policy, they will be attached directly to the user.",
		Attributes: map[string]schema.Attribute{
			"attached_policies": schema.ListAttribute{
				Description: "The RAM policies to attach to the user.",
				Required:    true,
				ElementType: types.StringType,
			},
			// NOTE: Avoid using 'policies' in new implementations; use 'CombinedPolicies' instead.
			// TODO: Remove this data transfer and 'policies' when said variable is no longer used.
			"policies": schema.ListNestedAttribute{
				Description: "[Deprecated] A list of policies.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"policy_name": schema.StringAttribute{
							Description: "The policy name.",
							Computed:    true,
						},
						"policy_document": schema.StringAttribute{
							Description: "The policy document of the RAM policy.",
							Computed:    true,
						},
					},
				},
			},
			"combined_policies": schema.ListNestedAttribute{
				Description: "A list of combined policies that are attached to users.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"policy_name": schema.StringAttribute{
							Description: "The policy name.",
							Computed:    true,
						},
						"policy_document": schema.StringAttribute{
							Description: "The policy document of the RAM policy.",
							Computed:    true,
						},
					},
				},
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
							Description: "The policy document of the RAM policy.",
							Computed:    true,
						},
					},
				},
			},
			"user_name": schema.StringAttribute{
				Description: "The name of the RAM user that attached to the policy.",
				Required:    true,
			},
		},
	}
}

func (r *iamPolicyResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(awsClients).iamClient
}

func (r *iamPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan *iamPolicyResourceModel
	getPlanDiags := req.Config.Get(ctx, &plan)
	resp.Diagnostics.Append(getPlanDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, currentPoliciesList, err := r.createPolicy(ctx, plan)
	if err != nil {
		resp.Diagnostics.AddError(
			"[API ERROR] Failed to Create the Policy.",
			err.Error(),
		)
		return
	}

	state := &iamPolicyResourceModel{}
	state.AttachedPolicies = plan.AttachedPolicies
	state.CombinedPolices = policy
	state.AttachedPoliciesDetail = currentPoliciesList
	state.UserName = plan.UserName

	if err := r.attachPolicyToUser(ctx, state); err != nil {
		resp.Diagnostics.AddError(
			"[API ERROR] Failed to Attach Policy to User.",
			err.Error(),
		)
		return
	}

	_, errReadPolicyDiags := r.readCombinedPolicy(ctx, state)
	resp.Diagnostics.Append(errReadPolicyDiags)
	if resp.Diagnostics.HasError() {
		return
	}

	setStateDiags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *iamPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state *iamPolicyResourceModel
	getStateDiags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(getStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// NOTE: Avoid using 'policies' in new implementations; use 'CombinedPolicies' instead.
	// TODO: Remove this data transfer and 'policies' when said variable is no longer used.
	if len(state.CombinedPolices) == 0 && len(state.Policies) != 0 {
		state.CombinedPolices = state.Policies
		state.Policies = nil
	}

	// This state will be using to compare with the current state.
	var oriState *iamPolicyResourceModel
	getOriStateDiags := req.State.Get(ctx, &oriState)
	resp.Diagnostics.Append(getOriStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// NOTE: Avoid using 'policies' in new implementations; use 'CombinedPolicies' instead.
	// TODO: Remove this data transfer and 'policies' when said variable is no longer used.
	if len(oriState.CombinedPolices) == 0 && len(oriState.Policies) != 0 {
		oriState.CombinedPolices = oriState.Policies
		state.Policies = nil
	}

	warnReadPolicyDiags, errReadPolicyDiags := r.readCombinedPolicy(ctx, state)
	resp.Diagnostics.Append(warnReadPolicyDiags, errReadPolicyDiags)
	if resp.Diagnostics.HasError() {
		return
	}

	setStateDiags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	warnReadPolicyDiags, errReadPolicyDiags = r.readAttachedPolicy(ctx, state, true)
	resp.Diagnostics.Append(warnReadPolicyDiags, errReadPolicyDiags)
	if resp.Diagnostics.HasError() {
		return
	}

	setStateDiags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if warnReadPolicyDiags == nil {
		compareEachPolicyDiags := r.compareEachPolicy(state, oriState)
		resp.Diagnostics.Append(compareEachPolicyDiags...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	setStateDiags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *iamPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state *iamPolicyResourceModel
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

	// NOTE: Avoid using 'policies' in new implementations; use 'CombinedPolicies' instead.
	// TODO: Remove this data transfer and 'policies' when said variable is no longer used.
	if len(state.CombinedPolices) == 0 && len(state.Policies) != 0 {
		state.CombinedPolices = state.Policies
		state.Policies = nil
	}

	warnReadPolicyDiags, errReadPolicyDiags := r.readAttachedPolicy(ctx, plan, false) //to prevent removal of combined policies, if user inputs non-existing attached policies
	resp.Diagnostics.Append(warnReadPolicyDiags, errReadPolicyDiags)
	if resp.Diagnostics.HasError() {
		return
	}

	removePolicyDiags := r.removePolicy(ctx, state)
	resp.Diagnostics.Append(removePolicyDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, currentPoliciesList, err := r.createPolicy(ctx, plan)
	if err != nil {
		resp.Diagnostics.AddError(
			"[API ERROR] Failed to Update the Policy.",
			err.Error(),
		)
		return
	}

	state.AttachedPolicies = plan.AttachedPolicies
	state.CombinedPolices = policy
	state.AttachedPoliciesDetail = currentPoliciesList
	state.UserName = plan.UserName

	if err := r.attachPolicyToUser(ctx, state); err != nil {
		resp.Diagnostics.AddError(
			"[API ERROR] Failed to Attach Policy to User.",
			err.Error(),
		)
		return
	}

	_, errReadPolicyDiags = r.readCombinedPolicy(ctx, state)
	resp.Diagnostics.Append(errReadPolicyDiags)
	if resp.Diagnostics.HasError() {
		return
	}

	setStateDiags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *iamPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state *iamPolicyResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	// NOTE: Avoid using 'policies' in new implementations; use 'CombinedPolicies' instead.
	// TODO: Remove this data transfer and 'policies' when said variable is no longer used.
	if len(state.CombinedPolices) == 0 && len(state.Policies) != 0 {
		state.CombinedPolices = state.Policies
		state.Policies = nil
	}

	removePolicyDiags := r.removePolicy(ctx, state)
	resp.Diagnostics.Append(removePolicyDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *iamPolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	policyDetailsState := []*policyDetail{}
	getPolicyDocumentResponse := &awsIamClient.GetPolicyVersionOutput{}
	policyNames := strings.Split(req.ID, ",")
	var username string

	var err error
	getPolicy := func() error {
		for _, policyName := range policyNames {
			policyName = strings.ReplaceAll(policyName, " ", "")

			// Retrieves the policy document for the policy
			policyArn, policyVersionId := r.getPolicyArn(ctx, policyName)

			getPolicyDocumentResponse, err = r.client.GetPolicyVersion(ctx, &awsIamClient.GetPolicyVersionInput{
				PolicyArn: aws.String(policyArn),
				VersionId: aws.String(policyVersionId),
			})
			if err != nil {
				handleAPIError(err)
			}

			// Retrieves the name of the user attached to the policy.
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

				policyDetail := policyDetail{
					PolicyName:     types.StringValue(policyName),
					PolicyDocument: types.StringValue(policyDocument),
				}
				policyDetailsState = append(policyDetailsState, &policyDetail)
			}

			if getPolicyEntities.PolicyUsers != nil {
				for _, user := range getPolicyEntities.PolicyUsers {
					username = *user.UserName
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

	var policyList []policyDetail
	for _, policy := range policyDetailsState {
		policies := policyDetail{
			PolicyName:     types.StringValue(policy.PolicyName.ValueString()),
			PolicyDocument: types.StringValue(policy.PolicyDocument.ValueString()),
		}

		policyList = append(policyList, policies)
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("user_name"), username)...)
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

func (r *iamPolicyResource) createPolicy(ctx context.Context, plan *iamPolicyResourceModel) (policiesList []*policyDetail, currentPoliciesList []*policyDetail, err error) {
	combinedPolicyStatements, notCombinedPolicies, currentPoliciesStatements, err := r.combinePolicyDocument(ctx, plan)
	if err != nil {
		return nil, nil, err
	}

	createPolicy := func() error {
		for i, policy := range combinedPolicyStatements {
			policyName := plan.UserName.ValueString() + "-" + strconv.Itoa(i+1)

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
	err = backoff.Retry(createPolicy, reconnectBackoff)

	if err != nil {
		return nil, nil, err
	}

	for i, policies := range combinedPolicyStatements {
		policyName := plan.UserName.ValueString() + "-" + strconv.Itoa(i+1)

		policyObj := &policyDetail{
			PolicyName:     types.StringValue(policyName),
			PolicyDocument: types.StringValue(policies),
		}

		policiesList = append(policiesList, policyObj)
	}

	// These policies will be attached directly to the user since splitting the
	// policy "statement" will be hitting the limitation of "maximum number of
	// attached policies" easily.
	for _, policy := range notCombinedPolicies {
		policyObj := &policyDetail{
			PolicyName:     types.StringValue(policy.policyName),
			PolicyDocument: types.StringValue(policy.policyDocument),
		}

		policiesList = append(policiesList, policyObj)
	}

	// These policies are used for comparing whether there is a differerence
	// between current policies in state file and in the console
	for _, policy := range currentPoliciesStatements {
		policyObj := &policyDetail{
			PolicyName:     types.StringValue(strings.Trim(policy.policyName, "\"")),
			PolicyDocument: types.StringValue(policy.policyDocument),
		}

		currentPoliciesList = append(currentPoliciesList, policyObj)
	}

	return policiesList, currentPoliciesList, nil
}

func (r *iamPolicyResource) readCombinedPolicy(ctx context.Context, state *iamPolicyResourceModel) (warnDiagnostics, errDiagnostics diag.Diagnostic) {
	policyDetailsState := []*policyDetail{}

	var warning, err error
	var ae smithy.APIError
	getPolicy := func() error {
		for _, combinedPolicy := range state.CombinedPolices {
			policyArn, policyVersionId := r.getPolicyArn(ctx, combinedPolicy.PolicyName.ValueString())

			getPolicyDocumentResponse, errDoc := r.client.GetPolicyVersion(ctx, &awsIamClient.GetPolicyVersionInput{
				PolicyArn: aws.String(policyArn),
				VersionId: aws.String(policyVersionId),
			})

			if errDoc != nil {
				if errors.As(err, &ae) {
					if ae.ErrorCode() == "NoSuchEntity " {
						// To detect if policy has been deleted after being attached.
						warning = errors.Join(warning, handleAPIError(errDoc))
					} else {
						err = errors.Join(err, handleAPIError(errDoc))
					}
				} else {
					err = errors.Join(err, handleAPIError(errDoc))
				}
				continue
			}

			getPolicyNameResponse, errName := r.client.GetPolicy(ctx, &awsIamClient.GetPolicyInput{
				PolicyArn: aws.String(policyArn),
			})

			if errName != nil {
				if errors.As(err, &ae) {
					if ae.ErrorCode() == "NoSuchEntity " {
						// To detect if policy has been deleted after being attached.
						warning = errors.Join(warning, handleAPIError(errName))
					} else {
						err = errors.Join(err, handleAPIError(errName))
					}
				} else {
					err = errors.Join(err, handleAPIError(errName))
				}
				continue
			}

			// Sometimes combined policies may be removed accidentally by human mistake or API error.
			if getPolicyDocumentResponse != nil && getPolicyNameResponse != nil {
				if (getPolicyDocumentResponse.PolicyVersion != nil) && (getPolicyNameResponse.Policy != nil) {
					policyDetail := &policyDetail{
						PolicyName:     types.StringValue(*getPolicyNameResponse.Policy.PolicyName),
						PolicyDocument: types.StringValue(*getPolicyDocumentResponse.PolicyVersion.Document),
					}
					policyDetailsState = append(policyDetailsState, policyDetail)
				}
			}
		}
		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second
	err = backoff.Retry(getPolicy, reconnectBackoff)
	if err != nil {
		errDiagnostics = diag.NewErrorDiagnostic(
			"[API ERROR] Failed to Read Combined Policy",
			err.Error(),
		)
		return nil, errDiagnostics
	}

	if warning != nil {
		warnDiagnostics = diag.NewWarningDiagnostic(
			"Combined Policies could not be found.",
			"The combined policies attached to the user may be deleted due to human mistake or API error. This resource will be re-created.\n\n"+
				warning.Error(),
		)

		state.AttachedPolicies = types.ListNull(types.StringType) //This is to ensure Update() is called
	}

	state.CombinedPolices = policyDetailsState

	return warnDiagnostics, errDiagnostics
}

func (r *iamPolicyResource) readAttachedPolicy(ctx context.Context, state *iamPolicyResourceModel, inRead bool) (warnDiagnostics, errDiagnostics diag.Diagnostic) {
	attachedPolicies := state.AttachedPolicies.Elements()
	policyDetailsState, warning, err := r.fetchPolicies(ctx, attachedPolicies, inRead)

	if err != nil {
		errDiagnostics = diag.NewErrorDiagnostic(
			"[API ERROR] Failed to Read Attached Policy",
			err.Error(),
		)
	}

	if warning != nil {
		warnDiagnostics = diag.NewWarningDiagnostic(
			"One (or more) of the Attached Policy could not be found.",
			"The policy used for Combined Policies may be deleted due to human mistake or API error.\n\n"+
				warning.Error(),
		)
	}

	state.AttachedPoliciesDetail = policyDetailsState
	if warnDiagnostics != nil {
		state.AttachedPolicies = types.ListNull(types.StringType) // Ensure Update() is called
	}

	return warnDiagnostics, errDiagnostics
}

func (r *iamPolicyResource) fetchPolicies(ctx context.Context, attachedPolicies []attr.Value, inRead bool) (policyDetailsState []*policyDetail, errNotExist, errOther error) {
	getPolicyDocumentResponse := &awsIamClient.GetPolicyVersionOutput{}
	getPolicyNameResponse := &awsIamClient.GetPolicyOutput{}
	var errDoc, errName error

	getPolicy := func() error {
		for _, policy := range attachedPolicies {
			policyArn, policyVersionId := r.getPolicyArn(ctx, strings.Trim(policy.String(), "\""))

			if policyArn == "" && policyVersionId == "" && inRead{
				errNotExist = errors.Join(errNotExist, fmt.Errorf("policy of %v does not exist. it may be deleted outside of terraform", policy))
				continue
			}


			getPolicyDocumentRequest := &awsIamClient.GetPolicyVersionInput{
				PolicyArn: aws.String(policyArn),
				VersionId: aws.String(policyVersionId),
			}

			getPolicyDocumentResponse, errDoc = r.client.GetPolicyVersion(ctx, getPolicyDocumentRequest)

			if errDoc != nil {
				errOther = errors.Join(errOther, handleAPIError(errDoc))
				continue
			}

			getPolicyNameRequest := &awsIamClient.GetPolicyInput{
				PolicyArn: aws.String(policyArn),
			}

			getPolicyNameResponse, errName = r.client.GetPolicy(ctx, getPolicyNameRequest)

			if errName != nil {
				errOther = errors.Join(errOther, handleAPIError(errDoc))
				continue
			}

			if getPolicyNameResponse != nil && getPolicyNameResponse.Policy != nil && getPolicyNameResponse.Policy.PolicyName != nil {
				if getPolicyDocumentResponse.PolicyVersion != nil && getPolicyDocumentResponse.PolicyVersion.Document != nil {
					tempPolicyDocument, err := url.QueryUnescape(*getPolicyDocumentResponse.PolicyVersion.Document)
					if err != nil {
						errOther = errors.Join(errOther, handleAPIError(errName))
					}

					policyDetail := policyDetail{
						PolicyName:     types.StringValue(*getPolicyNameResponse.Policy.PolicyName),
						PolicyDocument: types.StringValue(tempPolicyDocument),
					}
					policyDetailsState = append(policyDetailsState, &policyDetail)
				}
			}
		}
		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second
	backoff.Retry(getPolicy, reconnectBackoff)

	return policyDetailsState, errNotExist, errOther
}

func (r *iamPolicyResource) compareEachPolicy(newState, oriState *iamPolicyResourceModel) diag.Diagnostics {
	var driftedPolicies []string

	for _, oldPolicyDetailState := range oriState.AttachedPoliciesDetail {
		for _, currPolicyDetailState := range newState.AttachedPoliciesDetail {
			if oldPolicyDetailState.PolicyName.String() == currPolicyDetailState.PolicyName.String() {
				if oldPolicyDetailState.PolicyDocument.String() != currPolicyDetailState.PolicyDocument.String() {
					driftedPolicies = append(driftedPolicies, oldPolicyDetailState.PolicyName.String())
				}
			}
		}
	}

	if len(driftedPolicies) > 0 {
		driftedPoliciesMessage := fmt.Sprintf(
			"The following policies have drifted: %s. It may be caused by modifying the .json file outside of Terraform.",
			strings.Join(driftedPolicies, ", "),
		)

		newState.AttachedPolicies = types.ListNull(types.StringType) // Set the state to trigger an update.
		return diag.Diagnostics{
			diag.NewWarningDiagnostic(
				"Policy Drift Detected.",
				driftedPoliciesMessage,
			),
		}
	}

	return nil
}

func (r *iamPolicyResource) removePolicy(ctx context.Context, state *iamPolicyResourceModel) diag.Diagnostics {
	removePolicy := func() error {
		for _, combinedPolicy := range state.CombinedPolices {
			policyArn, _ := r.getPolicyArn(ctx, combinedPolicy.PolicyName.ValueString())

			detachPolicyFromUserRequest := &awsIamClient.DetachUserPolicyInput{
				PolicyArn: aws.String(policyArn),
				UserName:  aws.String(state.UserName.ValueString()),
			}

			deletePolicyRequest := &awsIamClient.DeletePolicyInput{
				PolicyArn: aws.String(policyArn),
			}

			if _, err := r.client.DetachUserPolicy(ctx, detachPolicyFromUserRequest); err != nil {
				handleAPIError(err)
			}

			if _, err := r.client.DeletePolicy(ctx, deletePolicyRequest); err != nil {
				handleAPIError(err)
			}
		}

		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second
	err := backoff.Retry(removePolicy, reconnectBackoff)
	if err != nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic(
				"[API ERROR] Failed to Delete Policy",
				err.Error(),
			),
		}
	}

	return nil
}

type simplePolicy struct {
	policyName     string
	policyDocument string
}

func (r *iamPolicyResource) combinePolicyDocument(ctx context.Context, plan *iamPolicyResourceModel) (finalPolicyDocument []string, excludedPolicy []simplePolicy, currentPolicyList []simplePolicy, err error) {
	attachedPolicies := plan.AttachedPolicies.Elements()
	policyDetailsState, _, err := r.fetchPolicies(ctx, attachedPolicies, false)

	const policyKeywordLen = 30

	if err != nil {
		return nil, nil, nil, err
	}

	currentLength := 0
	currentPolicyDocument := ""
	appendedPolicyDocument := make([]string, 0)

	for _, detail := range policyDetailsState {
		tempPolicyDocument := detail.PolicyDocument.ValueString()

		currentPolicyList = append(currentPolicyList, simplePolicy{
			policyName:     detail.PolicyName.ValueString(),
			policyDocument: tempPolicyDocument,
		})

		// If the policy itself have more than 6144 characters, then skip the combine
		// policy part since splitting the policy "statement" will be hitting the
		// limitation of "maximum number of attached policies" easily.
		noWhitespace := strings.Join(strings.Fields(tempPolicyDocument), "") //removes any whitespace including \t and \n
		if len(noWhitespace) > maxLength {
			excludedPolicy = append(excludedPolicy, simplePolicy{
				policyName:     detail.PolicyName.ValueString(),
				policyDocument: tempPolicyDocument,
			})
			continue
		}

		var data map[string]interface{}
		if err := json.Unmarshal([]byte(tempPolicyDocument), &data); err != nil {
			return nil, nil, nil, err
		}

		statementArr := data["Statement"].([]interface{})
		statementBytes, err := json.Marshal(statementArr)
		if err != nil {
			return nil, nil, nil, err
		}

		finalStatement := strings.Trim(string(statementBytes), "[]")
		currentLength += len(finalStatement)

		// Before further proceeding the current policy, we need to add a number of 30 to simulate the total length of completed policy to check whether it is already execeeded the max character length of 6144.
		// Number of 30 indicates the character length of neccessary policy keyword such as "Version" and "Statement" and some JSON symbols ({}, [])
		if (currentLength + policyKeywordLen) > maxLength {
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

	for _, policy := range appendedPolicyDocument {
		finalPolicyDocument = append(finalPolicyDocument, fmt.Sprintf(`{"Version":"2012-10-17","Statement":[%v]}`, policy))
	}

	return finalPolicyDocument, excludedPolicy, currentPolicyList, nil
}

func (r *iamPolicyResource) attachPolicyToUser(ctx context.Context, state *iamPolicyResourceModel) (err error) {
	attachPolicyToUser := func() error {
		for _, combinedPolicy := range state.CombinedPolices {
			policyArn, _ := r.getPolicyArn(ctx, combinedPolicy.PolicyName.ValueString())

			attachPolicyToUserRequest := &awsIamClient.AttachUserPolicyInput{
				PolicyArn: aws.String(policyArn),
				UserName:  aws.String(state.UserName.ValueString()),
			}

			if _, err := r.client.AttachUserPolicy(ctx, attachPolicyToUserRequest); err != nil {
				return handleAPIError(err)
			}
		}
		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second
	return backoff.Retry(attachPolicyToUser, reconnectBackoff)
}

func (r *iamPolicyResource) getPolicyArn(ctx context.Context, policyName string) (policyArn string, policyVersionId string) {
	listPolicies := func() error {
		listPoliciesResponse, err := r.client.ListPolicies(ctx, &awsIamClient.ListPoliciesInput{
			MaxItems: aws.Int32(1000),
			Scope:    "All",
		})
		if err != nil {
			return handleAPIError(err)
		}

		for _, policyObj := range listPoliciesResponse.Policies {
			if *policyObj.PolicyName == policyName {
				policyArn = *policyObj.Arn
				policyVersionId = *policyObj.DefaultVersionId
			}
		}
		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second
	backoff.Retry(listPolicies, reconnectBackoff)

	return policyArn, policyVersionId
}

func handleAPIError(err error) error {
	var ae smithy.APIError

	if errors.As(err, &ae) {
		if isAbleToRetry(ae.ErrorCode()) {
			return err
		} else {
			return backoff.Permanent(err)
		}
	} else {
		return backoff.Permanent(err)
	}
}
