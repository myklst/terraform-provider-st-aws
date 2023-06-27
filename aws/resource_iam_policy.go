package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	awsIamClient "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/cenkalti/backoff"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
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
	PolicyName     types.String `tfsdk:"policy_name"`
	PolicyDocument types.String `tfsdk:"policy_document"`
	Policies       types.List   `tfsdk:"policies"`
	UserName       types.String `tfsdk:"user_name"`
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
		Description: "Provides a RAM Policy resource.",
		Attributes: map[string]schema.Attribute{
			"policy_name": schema.StringAttribute{
				Description: "The policy name.",
				Required:    true,
			},
			"policy_document": schema.StringAttribute{
				Description: "The policy document of the RAM policy.",
				Required:    true,
			},
			"policies": schema.ListNestedAttribute{
				Description: "A list of policies.",
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
	getPlanDiags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(getPlanDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, err := r.createPolicy(ctx, plan)
	if err != nil {
		resp.Diagnostics.AddError(
			"[API ERROR] Failed to Create the Policy.",
			err.Error(),
		)
		return
	}

	state := &iamPolicyResourceModel{}
	state.PolicyName = plan.PolicyName
	state.PolicyDocument = plan.PolicyDocument
	state.Policies = types.ListValueMust(
		types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"policy_name":     types.StringType,
				"policy_document": types.StringType,
			},
		},
		policy,
	)
	state.UserName = plan.UserName

	if err := r.attachPolicyToUser(ctx, state); err != nil {
		resp.Diagnostics.AddError(
			"[API ERROR] Failed to Attach Policy to User.",
			err.Error(),
		)
		return
	}

	readPolicyDiags := r.readPolicy(ctx, state)
	resp.Diagnostics.Append(readPolicyDiags...)
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

	readPolicyDiags := r.readPolicy(ctx, state)
	resp.Diagnostics.Append(readPolicyDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	listPoliciesForUser := func() error {
		listPoliciesForUserRequest := &awsIamClient.ListUserPoliciesInput{
			UserName: aws.String(state.UserName.ValueString()),
		}

		_, err := r.client.ListUserPolicies(ctx, listPoliciesForUserRequest)
		if err != nil {
			handleAPIError(err)
		}
		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second
	err := backoff.Retry(listPoliciesForUser, reconnectBackoff)
	if err != nil {
		resp.Diagnostics.AddError(
			"[API ERROR] Failed to Read Users for Group",
			err.Error(),
		)
		return
	}

	setStateDiags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *iamPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state *iamPolicyResourceModel
	getPlanDiags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(getPlanDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	getStateDiags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(getStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	removePolicyDiags := r.removePolicy(ctx, state)
	resp.Diagnostics.Append(removePolicyDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, err := r.createPolicy(ctx, plan)
	if err != nil {
		resp.Diagnostics.AddError(
			"[API ERROR] Failed to Update the Policy.",
			err.Error(),
		)
		return
	}

	state.PolicyName = plan.PolicyName
	state.PolicyDocument = plan.PolicyDocument
	state.Policies = types.ListValueMust(
		types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"policy_name":     types.StringType,
				"policy_document": types.StringType,
			},
		},
		policy,
	)
	state.UserName = plan.UserName

	if err := r.attachPolicyToUser(ctx, state); err != nil {
		resp.Diagnostics.AddError(
			"[API ERROR] Failed to Attach Policy to User.",
			err.Error(),
		)
		return
	}

	readPolicyDiags := r.readPolicy(ctx, state)
	resp.Diagnostics.Append(readPolicyDiags...)
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

	removePolicyDiags := r.removePolicy(ctx, state)
	resp.Diagnostics.Append(removePolicyDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *iamPolicyResource) createPolicy(ctx context.Context, plan *iamPolicyResourceModel) (policiesList []attr.Value, err error) {
	formattedPolicy := r.getPolicyDocument(ctx, plan)

	createPolicy := func() error {
		for i, policy := range formattedPolicy {
			policyName := plan.PolicyName.ValueString() + "-" + strconv.Itoa(i+1)

			createPolicyRequest := &awsIamClient.CreatePolicyInput{
				PolicyName:     aws.String(policyName),
				PolicyDocument: aws.String(policy),
			}

			if _, err := r.client.CreatePolicy(ctx, createPolicyRequest); err != nil {
				handleAPIError(err)
			}
		}

		return nil
	}

	for i, policies := range formattedPolicy {
		policyName := plan.PolicyName.ValueString() + "-" + strconv.Itoa(i+1)

		policyObj := types.ObjectValueMust(
			map[string]attr.Type{
				"policy_name":     types.StringType,
				"policy_document": types.StringType,
			},
			map[string]attr.Value{
				"policy_name":     types.StringValue(policyName),
				"policy_document": types.StringValue(policies),
			},
		)

		policiesList = append(policiesList, policyObj)
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second
	return policiesList, backoff.Retry(createPolicy, reconnectBackoff)
}

func (r *iamPolicyResource) readPolicy(ctx context.Context, plan *iamPolicyResourceModel) diag.Diagnostics {
	getPolicyDocumentResponse := &awsIamClient.GetPolicyVersionOutput{}
	getPolicyNameResponse := &awsIamClient.GetPolicyOutput{}

	state := &iamPolicyResourceModel{}
	state.Policies = plan.Policies

	var err error
	getPolicy := func() error {
		data := make(map[string]string)

		for _, policies := range state.Policies.Elements() {
			json.Unmarshal([]byte(policies.String()), &data)

			policyName := data["policy_name"]
			policyArn := r.getPolicyArn(ctx, policyName)

			getPolicyDocumentResponse, err = r.client.GetPolicyVersion(ctx, &awsIamClient.GetPolicyVersionInput{
				PolicyArn: aws.String(policyArn),
				VersionId: aws.String("v1"),
			})
			if err != nil {
				handleAPIError(err)
			}

			getPolicyNameResponse, err = r.client.GetPolicy(ctx, &awsIamClient.GetPolicyInput{
				PolicyArn: aws.String(policyArn),
			})
			if err != nil {
				handleAPIError(err)
			}
		}
		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second
	err = backoff.Retry(getPolicy, reconnectBackoff)
	if err != nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic(
				"[API ERROR] Failed to Read Policy.",
				err.Error(),
			),
		}
	}

	policyDetailsState := []*policyDetail{}
	if (getPolicyDocumentResponse.PolicyVersion != nil) && (getPolicyNameResponse.Policy != nil) {
		policyDetail := policyDetail{
			PolicyName:     types.StringValue(*getPolicyNameResponse.Policy.PolicyName),
			PolicyDocument: types.StringValue(*getPolicyDocumentResponse.PolicyVersion.Document),
		}
		policyDetailsState = append(policyDetailsState, &policyDetail)
	}

	for _, policy := range policyDetailsState {
		state.Policies = types.ListValueMust(
			types.ObjectType{
				AttrTypes: map[string]attr.Type{
					"policy_name":     types.StringType,
					"policy_document": types.StringType,
				},
			},
			[]attr.Value{
				types.ObjectValueMust(
					map[string]attr.Type{
						"policy_name":     types.StringType,
						"policy_document": types.StringType,
					},
					map[string]attr.Value{
						"policy_name":     types.StringValue(policy.PolicyName.ValueString()),
						"policy_document": types.StringValue(policy.PolicyDocument.ValueString()),
					},
				),
			},
		)
	}
	return nil
}

func (r *iamPolicyResource) removePolicy(ctx context.Context, state *iamPolicyResourceModel) diag.Diagnostics {
	data := make(map[string]string)

	for _, policies := range state.Policies.Elements() {
		json.Unmarshal([]byte(policies.String()), &data)

		policyName := data["policy_name"]
		policyArn := r.getPolicyArn(ctx, policyName)

		detachPolicyFromUserRequest := &awsIamClient.DetachUserPolicyInput{
			PolicyArn: aws.String(policyArn),
			UserName:  aws.String(state.UserName.ValueString()),
		}

		deletePolicyRequest := &awsIamClient.DeletePolicyInput{
			PolicyArn: aws.String(policyArn),
		}

		if _, err := r.client.DetachUserPolicy(ctx, detachPolicyFromUserRequest); err != nil {
			return diag.Diagnostics{
				diag.NewErrorDiagnostic(
					"[API ERROR] Failed to Detach Policy from User.",
					err.Error(),
				),
			}
		}

		if _, err := r.client.DeletePolicy(ctx, deletePolicyRequest); err != nil {
			return diag.Diagnostics{
				diag.NewErrorDiagnostic(
					"[API ERROR] Failed to Delete Policy.",
					err.Error(),
				),
			}
		}
	}
	return nil
}

func (r *iamPolicyResource) getPolicyDocument(ctx context.Context, plan *iamPolicyResourceModel) []string {
	currentLength := 0
	currentPolicyDocument := ""
	appendedPolicyDocument := make([]string, 0)
	finalPolicyDocument := make([]string, 0)

	tempDocument := plan.PolicyDocument.ValueString()
	tempDocument = strings.TrimSpace(tempDocument)
	tempDocument = strings.TrimPrefix(tempDocument, "[")

	lastChar := tempDocument[len(tempDocument)-2]

	if lastChar == ',' {
		tempDocument = strings.TrimSuffix(tempDocument, ",]")
	} else {
		tempDocument = strings.TrimSuffix(tempDocument, "]")
	}

	policyList := strings.Split(tempDocument, ",")

	for i, policy := range policyList {
		policyList[i] = strings.TrimSpace(policy)
		policyList[i] = strings.Trim(policyList[i], "\"")
	}

	getPolicy := func() error {
		for i, policy := range policyList {
			policyArn := r.getPolicyArn(ctx, policy)

			var err error
			getPolicyResponse, err := r.client.GetPolicyVersion(ctx, &awsIamClient.GetPolicyVersionInput{
				PolicyArn: aws.String(policyArn),
				VersionId: aws.String("v1"),
			})
			if err != nil {
				handleAPIError(err)
			}

			tempPolicyDocument, err := url.QueryUnescape(*getPolicyResponse.PolicyVersion.Document)

			var data map[string]interface{}
			err = json.Unmarshal([]byte(tempPolicyDocument), &data)

			statementArr := data["Statement"].([]interface{})
			statementBytes, _ := json.MarshalIndent(statementArr, "", "  ")

			removeSpaces := strings.ReplaceAll(string(statementBytes), " ", "")
			replacer := strings.NewReplacer("\n", "")
			removeParagraphs := replacer.Replace(removeSpaces)

			finalStatement := strings.Trim(removeParagraphs, "[]")

			currentLength += len(finalStatement)

			if (currentLength + 30) > maxLength {
				lastCommaIndex := strings.LastIndex(currentPolicyDocument, ",")
				if lastCommaIndex >= 0 {
					currentPolicyDocument = currentPolicyDocument[:lastCommaIndex] + currentPolicyDocument[lastCommaIndex+1:]
				}

				appendedPolicyDocument = append(appendedPolicyDocument, currentPolicyDocument)
				currentPolicyDocument = finalStatement + ","
				currentLength = len(finalStatement)
			} else {
				currentPolicyDocument += finalStatement + ","
			}

			if i == len(policyList)-1 && (currentLength+30) <= maxLength {
				lastCommaIndex := strings.LastIndex(currentPolicyDocument, ",")
				if lastCommaIndex >= 0 {
					currentPolicyDocument = currentPolicyDocument[:lastCommaIndex] + currentPolicyDocument[lastCommaIndex+1:]
				}

				appendedPolicyDocument = append(appendedPolicyDocument, currentPolicyDocument)
			}
		}

		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second
	backoff.Retry(getPolicy, reconnectBackoff)

	for _, policy := range appendedPolicyDocument {
		finalPolicyDocument = append(finalPolicyDocument, fmt.Sprintf(`{"Version":"2012-10-17","Statement":[%v]}`, policy))
	}

	return finalPolicyDocument
}

func (r *iamPolicyResource) attachPolicyToUser(ctx context.Context, state *iamPolicyResourceModel) (err error) {
	data := make(map[string]string)

	attachPolicyToUser := func() error {
		for _, policies := range state.Policies.Elements() {
			json.Unmarshal([]byte(policies.String()), &data)

			policyName := data["policy_name"]
			policyArn := r.getPolicyArn(ctx, policyName)

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

func (r *iamPolicyResource) getPolicyArn(ctx context.Context, policyName string) (policyArn string) {
	listPolicies := func() error {
		listPoliciesResponse, err := r.client.ListPolicies(ctx, &awsIamClient.ListPoliciesInput{
			Scope: "All",
		})
		if err != nil {
			return handleAPIError(err)
		}

		for _, policyObj := range listPoliciesResponse.Policies {
			if *policyObj.PolicyName == policyName {
				policyArn = *policyObj.Arn
			}
		}
		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second
	backoff.Retry(listPolicies, reconnectBackoff)

	return policyArn
}

func handleAPIError(err error) error {
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
