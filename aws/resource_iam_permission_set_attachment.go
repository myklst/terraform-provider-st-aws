package aws

import (
	"context"
	"errors"
	"fmt"
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
	permissionSetAttachmentKeywordLength = 30
	permissionSetAttachmentMaxLength     = 6144
)

var (
	_ resource.Resource              = &iamPermissionSetAttachmentResource{}
	_ resource.ResourceWithConfigure = &iamPermissionSetAttachmentResource{}
)

func NewIamPermissionSetAttachmentResource() resource.Resource {
	return &iamPermissionSetAttachmentResource{}
}

type iamPermissionSetAttachmentResource struct {
	client *awsIamClient.Client
	sso    *awsSsoAdminClient.Client
}

type iamPermissionSetAttachmentResourceModel struct {
	PermissionSetName types.String `tfsdk:"permission_set_name"`
	InstanceArn       types.String `tfsdk:"instance_arn"`
	PermissionSetArn  types.String `tfsdk:"permission_set_arn"`
	PolicyPath        types.String `tfsdk:"policy_path"`
	AttachedPolicies  types.List   `tfsdk:"attached_policies"`
}

func (r *iamPermissionSetAttachmentResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_iam_permission_set_attachment"
}

func (r *iamPermissionSetAttachmentResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provides an IAM Policy resource that manages policy content " +
			"exceeding character limits by splitting it into smaller segments. " +
			"These segments are combined to form a complete policy and attached to the chosen target. " +
			"Policies like `ReadOnlyAccess` that exceed the maximum length are attached directly.",
		Attributes: map[string]schema.Attribute{
			"permission_set_name": schema.StringAttribute{
				Description: "The permission set name.",
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
			"attached_policies": schema.ListAttribute{
				Description: "List of IAM policy.",
				ElementType: types.StringType,
				Required:    true,
			},
		},
	}
}

func (r *iamPermissionSetAttachmentResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(awsClients).iamClient
	r.sso = req.ProviderData.(awsClients).ssoAdminClient
}

func (r *iamPermissionSetAttachmentResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// If the entire plan is null, the resource is planned for destruction.
	if req.Config.Raw.IsNull() {
		fmt.Println("Plan is null; skipping ModifyPlan.")
		return
	}

	var plan *iamPermissionSetAttachmentResourceModel
	if diags := req.Config.Get(ctx, &plan); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	// Check if PermissionSet block is config. Set default path "/".
	if plan.PolicyPath.IsNull() || plan.PolicyPath.IsUnknown() || plan.PolicyPath.ValueString() == "" {
		plan.PolicyPath = types.StringValue("/") // The default policy path is "/".
	}

}

func (r *iamPermissionSetAttachmentResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan *iamPermissionSetAttachmentResourceModel
	getPlanDiags := req.Config.Get(ctx, &plan)
	resp.Diagnostics.Append(getPlanDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var policies []string
	plan.AttachedPolicies.ElementsAs(ctx, &policies, false)

	state := &iamPermissionSetAttachmentResourceModel{
		PermissionSetName: plan.PermissionSetName,
		InstanceArn:       plan.InstanceArn,
		PermissionSetArn:  plan.PermissionSetArn,
		PolicyPath:        plan.PolicyPath,
		AttachedPolicies:  plan.AttachedPolicies,
	}

	attachErrs := r.attachPolicyToPermissionSet(ctx, state, 10*time.Minute)

	if len(attachErrs) > 0 {
		addDiagnostics(&resp.Diagnostics, "error", "[API ERROR] Failed to attach policy to target.", attachErrs, "")
		return
	}

	setStateDiags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
}

func (r *iamPermissionSetAttachmentResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state *iamPermissionSetAttachmentResourceModel
	getStateDiags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(getStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// This state will be using to compare with the current state.
	var oriState *iamPermissionSetAttachmentResourceModel
	getOriStateDiags := req.State.Get(ctx, &oriState)
	resp.Diagnostics.Append(getOriStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	setStateDiags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *iamPermissionSetAttachmentResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state *iamPermissionSetAttachmentResourceModel
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

	removePolicyErr := r.removePolicy(ctx, state)
	addDiagnostics(
		&resp.Diagnostics,
		"error",
		fmt.Sprintf("[API ERROR] Failed to Remove Policies for %v: Unexpected Error!", state.PermissionSetName),
		removePolicyErr,
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

	state = &iamPermissionSetAttachmentResourceModel{
		PermissionSetName: plan.PermissionSetName,
		InstanceArn:       plan.InstanceArn,
		PermissionSetArn:  plan.PermissionSetArn,
		PolicyPath:        plan.PolicyPath,
		AttachedPolicies:  plan.AttachedPolicies,
	}

	attachErrs := r.attachPolicyToPermissionSet(ctx, state, 10*time.Minute)

	if len(attachErrs) > 0 {
		addDiagnostics(&resp.Diagnostics, "error", "[API ERROR] Failed to attach policy to target.", attachErrs, "")
		return
	}
}

func (r *iamPermissionSetAttachmentResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state *iamPermissionSetAttachmentResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// removePolicy.
	removePolicyUnexpectedErr := r.removePolicy(ctx, state)
	addDiagnostics(
		&resp.Diagnostics,
		"error",
		fmt.Sprintf("[API ERROR] Failed to Remove Policies for %v: Unexpected Error!", state.PermissionSetName),
		removePolicyUnexpectedErr,
		"",
	)
	if resp.Diagnostics.HasError() {
		return
	}
}

// removePolicy will detach the combined policies from user.
//
// Parameters:
//   - state: The recorded state configurations.
func (r *iamPermissionSetAttachmentResource) removePolicy(ctx context.Context, state *iamPermissionSetAttachmentResourceModel) (unexpectedError []error) {
	var ae smithy.APIError

	var policyNames []string

	diags := state.AttachedPolicies.ElementsAs(ctx, &policyNames, false)
	if diags.HasError() {
		return
	}

	removePolicy := func() error {
		instanceArn := state.InstanceArn.ValueString()
		permissionSetArn := state.PermissionSetArn.ValueString()

		changed := false
		detachCustomerManagedPolocies := false

		for _, policyName := range policyNames {
			policyArn, _, err := getPolicyArnHelper(ctx, r.client, policyName)
			if err != nil {
				detachCustomerManagedPolocies = true
				continue
			}

			a, err := arn.Parse(policyArn)
			if err != nil {
				return fmt.Errorf("invalid policy ARN %q: %w", policyArn, err)
			}

			if a.AccountID != "aws" {
				detachCustomerManagedPolocies = true
				continue
			}

			// AWS-managed policy detach
			if _, err := r.sso.DetachManagedPolicyFromPermissionSet(ctx, &awsSsoAdminClient.DetachManagedPolicyFromPermissionSetInput{
				InstanceArn:      aws.String(instanceArn),
				PermissionSetArn: aws.String(permissionSetArn),
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

			changed = true
		}

		// Detach customer-managed policies
		if detachCustomerManagedPolocies {
			if detErr := errors.Join(
				r.detachCustomerPoliciesFromPermissionSet(ctx, state)...,
			); detErr != nil {
				return fmt.Errorf("[API ERROR] Failed to detach customer-managed policies from Permission Set: %w", detErr)
			}

			changed = true
		}

		// Provision
		if changed {
			if ok, errs := r.provisionPermissionSetAllWait(ctx, state, 10*time.Minute); !ok {
				return fmt.Errorf("[API ERROR] Provisioning did not complete: %w", errors.Join(errs...))
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
func (r *iamPermissionSetAttachmentResource) attachCustomerPoliciesToPermissionSet(ctx context.Context, state *iamPermissionSetAttachmentResourceModel, policies []string) (unexpectedError []error) {
	attachCustomerPoliciesToPermissionSet := func() error {
		path := state.PolicyPath.ValueString()
		if path == "" {
			path = "/"
		}

		for _, policy := range policies {
			attachCustomerManagedPoliciesReferenceToPermissionSetInputRequest := &awsSsoAdminClient.AttachCustomerManagedPolicyReferenceToPermissionSetInput{
				InstanceArn:      aws.String(state.InstanceArn.ValueString()),
				PermissionSetArn: aws.String(state.PermissionSetArn.ValueString()),
				CustomerManagedPolicyReference: &ssoTypes.CustomerManagedPolicyReference{
					Name: aws.String(policy),
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
func (r *iamPermissionSetAttachmentResource) attachAWSManagedPoliciesToPermissionSet(ctx context.Context, state *iamPermissionSetAttachmentResourceModel, awsManagedPolicyArns []string) (unexpectedError []error) {
	attachAWSManagedPoliciesToPermissionSet := func() error {
		for _, awsManagedPolicyArn := range awsManagedPolicyArns {
			attachManagedPolicyToPermissionSetInputRequest := &awsSsoAdminClient.AttachManagedPolicyToPermissionSetInput{
				InstanceArn:      aws.String(state.InstanceArn.ValueString()),
				PermissionSetArn: aws.String(state.PermissionSetArn.ValueString()),
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
func (r *iamPermissionSetAttachmentResource) attachPolicyToPermissionSet(ctx context.Context, state *iamPermissionSetAttachmentResourceModel, provisionTimeout time.Duration) (unexpectedErrs []error) {
	prefix := state.PermissionSetName.ValueString() + "-"

	var customerManagedPolicy []string
	var awsManagedPolicy []string
	var policyNames []string

	diags := state.AttachedPolicies.ElementsAs(ctx, &policyNames, false)
	if diags.HasError() {
		return
	}

	for _, policyName := range policyNames {
		if strings.HasPrefix(policyName, prefix) {
			customerManagedPolicy = append(customerManagedPolicy, policyName)
		} else {
			awsManagedPolicy = append(awsManagedPolicy, policyName)
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
			resolvedArn, _, err := getPolicyArnHelper(ctx, r.client, awsManagedPolicyArn)
			if err != nil || resolvedArn == "" {
				if err == nil {
					err = fmt.Errorf("policy %q not found", awsManagedPolicyArn)
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

// detachCustomerPoliciesFromPermissionSet detaches the specified customer-managed policy
// references from a Permission Set and waits until each (Name, Path) reference disappears.
//
// Parameters
//   - ctx: request context (cancellation/deadline honored by retries)
//   - state: model containing Permission Set identifiers and the target policy names in CombinedPolicesDetail.
//
// Returns
//   - err: Error.
func (r *iamPermissionSetAttachmentResource) detachCustomerPoliciesFromPermissionSet(ctx context.Context, state *iamPermissionSetAttachmentResourceModel) (unexpectedError []error) {
	// To ensure the policy has been fully detach, keep on polls the `ListCustomerManagedPolicyReferencesInPermissionSet`
	// until the (Name, Path) reference disappears.
	waitDetachCustomerPoliciesFromPermissionSet := func(name, path string, maxWait time.Duration) error {
		if strings.TrimSpace(path) == "" {
			path = "/"
		}
		listCustomerManagedPolicyReferencesInPermissionSetRequest := func() error {
			listCustomerManagedPolicyReferencesInPermissionSet, err := r.sso.ListCustomerManagedPolicyReferencesInPermissionSet(ctx,
				&awsSsoAdminClient.ListCustomerManagedPolicyReferencesInPermissionSetInput{
					InstanceArn:      aws.String(state.InstanceArn.ValueString()),
					PermissionSetArn: aws.String(state.PermissionSetArn.ValueString()),
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
				InstanceArn:      aws.String(state.InstanceArn.ValueString()),
				PermissionSetArn: aws.String(state.PermissionSetArn.ValueString()),
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

			_, err := r.sso.DetachCustomerManagedPolicyReferenceFromPermissionSet(ctx,
				&awsSsoAdminClient.DetachCustomerManagedPolicyReferenceFromPermissionSetInput{
					InstanceArn:      aws.String(state.InstanceArn.ValueString()),
					PermissionSetArn: aws.String(state.PermissionSetArn.ValueString()),
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
func (r *iamPermissionSetAttachmentResource) provisionPermissionSetAllWait(ctx context.Context, state *iamPermissionSetAttachmentResourceModel, maxWait time.Duration) (ok bool, unexpectedError []error) {
	var reqID string
	provisionPermissionSetRequest := func() error {
		provisionPermissionSet, err := r.sso.ProvisionPermissionSet(ctx, &awsSsoAdminClient.ProvisionPermissionSetInput{
			InstanceArn:      aws.String(state.InstanceArn.ValueString()),
			PermissionSetArn: aws.String(state.PermissionSetArn.ValueString()),
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
			InstanceArn:                     aws.String(state.InstanceArn.ValueString()),
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
