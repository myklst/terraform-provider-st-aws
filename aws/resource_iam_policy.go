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
	"github.com/aws/aws-sdk-go/aws/awserr"
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
	AttachedPolicies types.List   `tfsdk:"attached_policies"`
	Policies         types.List   `tfsdk:"policies"`
	UserName         types.String `tfsdk:"user_name"`
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
		Description: "Provides a RAM Policy resource that manages policy content exceeding character limits by splitting it into smaller segments. These segments are combined to form a complete policy attached to the user.",
		Attributes: map[string]schema.Attribute{
			"attached_policies": schema.ListAttribute{
				Description: "The RAM policies to attach to the user.",
				Required:    true,
				ElementType: types.StringType,
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
	state.AttachedPolicies = plan.AttachedPolicies
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

	state.AttachedPolicies = plan.AttachedPolicies
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

func (r *iamPolicyResource) createPolicy(ctx context.Context, plan *iamPolicyResourceModel) (policiesList []attr.Value, err error) {
	formattedPolicy, err := r.getPolicyDocument(ctx, plan)
	if err != nil {
		return nil, err
	}

	createPolicy := func() error {
		for i, policy := range formattedPolicy {
			policyName := plan.UserName.ValueString() + "-" + strconv.Itoa(i+1)

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
		policyName := plan.UserName.ValueString() + "-" + strconv.Itoa(i+1)

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

func (r *iamPolicyResource) readPolicy(ctx context.Context, state *iamPolicyResourceModel) diag.Diagnostics {
	policyDetailsState := []*policyDetail{}
	getPolicyDocumentResponse := &awsIamClient.GetPolicyVersionOutput{}
	getPolicyNameResponse := &awsIamClient.GetPolicyOutput{}

	var err error
	getPolicy := func() error {
		data := make(map[string]string)

		for _, policies := range state.Policies.Elements() {
			json.Unmarshal([]byte(policies.String()), &data)

			policyName := data["policy_name"]
			policyArn, policyVersionId := r.getPolicyArn(ctx, policyName)

			getPolicyDocumentResponse, err = r.client.GetPolicyVersion(ctx, &awsIamClient.GetPolicyVersionInput{
				PolicyArn: aws.String(policyArn),
				VersionId: aws.String(policyVersionId),
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

			if getPolicyDocumentResponse != nil && getPolicyNameResponse != nil {
				if (getPolicyDocumentResponse.PolicyVersion != nil) && (getPolicyNameResponse.Policy != nil) {
					policyDetail := policyDetail{
						PolicyName:     types.StringValue(*getPolicyNameResponse.Policy.PolicyName),
						PolicyDocument: types.StringValue(*getPolicyDocumentResponse.PolicyVersion.Document),
					}
					policyDetailsState = append(policyDetailsState, &policyDetail)
				}
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

	if len(policyDetailsState) > 0 {
		state = &iamPolicyResourceModel{}
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
	} else {
		state.AttachedPolicies = types.ListNull(types.StringType)
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
						"policy_name":     types.StringNull(),
						"policy_document": types.StringNull(),
					},
				),
			},
		)
		state.UserName = types.StringNull()
	}
	return nil
}

func (r *iamPolicyResource) removePolicy(ctx context.Context, state *iamPolicyResourceModel) diag.Diagnostics {
	data := make(map[string]string)

	removePolicy := func() error {
		for _, policies := range state.Policies.Elements() {
			json.Unmarshal([]byte(policies.String()), &data)

			policyName := data["policy_name"]
			policyArn, _ := r.getPolicyArn(ctx, policyName)

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

func (r *iamPolicyResource) getPolicyDocument(ctx context.Context, plan *iamPolicyResourceModel) (finalPolicyDocument []string, err error) {
	policyName := ""
	currentLength := 0
	currentPolicyDocument := ""
	appendedPolicyDocument := make([]string, 0)
	finalPolicyDocument = make([]string, 0)

	var getPolicyResponse *awsIamClient.GetPolicyVersionOutput

	for i, policy := range plan.AttachedPolicies.Elements() {
		policyName = policy.String()
		policyName := strings.TrimPrefix(strings.TrimSuffix(policyName, "\""), "\"")
		policyArn, policyVersionId := r.getPolicyArn(ctx, policyName)

		getPolicy := func() error {
			var err error
			getPolicyResponse, err = r.client.GetPolicyVersion(ctx, &awsIamClient.GetPolicyVersionInput{
				PolicyArn: aws.String(policyArn),
				VersionId: aws.String(policyVersionId),
			})
			if err != nil {
				handleAPIError(err)
			}
			return nil
		}

		reconnectBackoff := backoff.NewExponentialBackOff()
		reconnectBackoff.MaxElapsedTime = 30 * time.Second
		backoff.Retry(getPolicy, reconnectBackoff)

		if getPolicyResponse != nil {
			if getPolicyResponse.PolicyVersion != nil {
				tempPolicyDocument, err := url.QueryUnescape(*getPolicyResponse.PolicyVersion.Document)
				if err != nil {
					return nil, err
				}

				var data map[string]interface{}
				if err := json.Unmarshal([]byte(tempPolicyDocument), &data); err != nil {
					return nil, err
				}

				statementArr := data["Statement"].([]interface{})
				statementBytes, err := json.MarshalIndent(statementArr, "", "  ")
				if err != nil {
					return nil, err
				}

				removeSpaces := strings.ReplaceAll(string(statementBytes), " ", "")
				replacer := strings.NewReplacer("\n", "")
				removeParagraphs := replacer.Replace(removeSpaces)

				finalStatement := strings.Trim(removeParagraphs, "[]")

				currentLength += len(finalStatement)

				// Before further proceeding the current policy, we need to add a number of 30 to simulate the total length of completed policy to check whether it is already execeeded the max character length of 6144.
				// Number of 30 indicates the character length of neccessary policy keyword such as "Version" and "Statement" and some JSON symbols ({}, [])
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

				if i == len(plan.AttachedPolicies.Elements())-1 && (currentLength+30) <= maxLength {
					lastCommaIndex := strings.LastIndex(currentPolicyDocument, ",")
					if lastCommaIndex >= 0 {
						currentPolicyDocument = currentPolicyDocument[:lastCommaIndex] + currentPolicyDocument[lastCommaIndex+1:]
					}

					appendedPolicyDocument = append(appendedPolicyDocument, currentPolicyDocument)
				}
			}
		} else {
			return nil, errors.New(fmt.Sprintf("The %v policy not found.", policyName))
		}
	}

	if len(appendedPolicyDocument) > 0 {
		for _, policy := range appendedPolicyDocument {
			finalPolicyDocument = append(finalPolicyDocument, fmt.Sprintf(`{"Version":"2012-10-17","Statement":[%v]}`, policy))
		}
	}

	return finalPolicyDocument, nil
}

func (r *iamPolicyResource) attachPolicyToUser(ctx context.Context, state *iamPolicyResourceModel) (err error) {
	data := make(map[string]string)

	attachPolicyToUser := func() error {
		for _, policies := range state.Policies.Elements() {
			json.Unmarshal([]byte(policies.String()), &data)

			policyName := data["policy_name"]
			policyArn, _ := r.getPolicyArn(ctx, policyName)

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
