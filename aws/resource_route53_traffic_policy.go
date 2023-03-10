package aws

import (
	"context"
	"fmt"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	awsRoute53Client "github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
)

var (
	_ resource.Resource                = &route53Resource{}
	_ resource.ResourceWithConfigure   = &route53Resource{}
	_ resource.ResourceWithImportState = &route53Resource{}
)

func NewRoute53Resource() resource.Resource {
	return &route53Resource{}
}

type route53Resource struct {
	client *awsRoute53Client.Client
}

type route53ResourceModel struct {
	ID       types.String `tfsdk:"id"`
	Document types.String `tfsdk:"document"`
	Name     types.String `tfsdk:"name"`
	Comment  types.String `tfsdk:"comment"`
	Version  types.Int64  `tfsdk:"version"`
}

// Metadata returns the resource Route53 traffic policy type name.
func (r *route53Resource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_route53_traffic_policy"
}

// Schema defines the schema for the Route53 traffic policy resource.
func (r *route53Resource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Route53 Traffic Policy.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Traffic Policy ID.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"document": schema.StringAttribute{
				Description: "Traffic Policy in JSON format.",
				Required:    true,
			},
			"name": schema.StringAttribute{
				Description: "Traffic Policy name.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"comment": schema.StringAttribute{
				Description: "Traffic Policy comment.",
				Required:    true,
			},
			"version": schema.Int64Attribute{
				Description: "Traffic Policy version",
				Computed:    true,
			},
		},
	}
}

// Configure adds the provider configured client to the resource.
func (r *route53Resource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(awsClients).route53Client
}

func (r *route53Resource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan *route53ResourceModel
	getStateDiags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(getStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	createTrafficPolicyResponse := &awsRoute53Client.CreateTrafficPolicyOutput{}
	createTrafficPolicy := func() error {
		name := plan.Name.ValueString()
		document := plan.Document.ValueString()
		comment := plan.Comment.ValueString()

		var err error
		createTrafficPolicyResponse, err = r.client.CreateTrafficPolicy(ctx, &awsRoute53Client.CreateTrafficPolicyInput{
			Document: aws.String(document),
			Name:     aws.String(name),
			Comment:  aws.String(comment),
		})
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				if isAbleToRetry(aerr.Code()) {
					return err
				} else {
					return backoff.Permanent(err)
				}
			} else {
				return backoff.Permanent(err)
			}
		}

		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second

	err := backoff.Retry(createTrafficPolicy, reconnectBackoff)
	if err != nil {
		resp.Diagnostics.AddError(
			"[API ERROR] Failed to create traffic policy",
			err.Error(),
		)
		return
	}

	state := &route53ResourceModel{}
	// Map response body to schema and populate Computed attribute values.
	state.ID = types.StringValue(*createTrafficPolicyResponse.TrafficPolicy.Id)
	state.Name = types.StringValue(*createTrafficPolicyResponse.TrafficPolicy.Name)
	state.Comment = types.StringValue(*createTrafficPolicyResponse.TrafficPolicy.Comment)
	state.Document = types.StringValue(*createTrafficPolicyResponse.TrafficPolicy.Document)
	state.Version = types.Int64Value(int64(*createTrafficPolicyResponse.TrafficPolicy.Version))

	// Set state to fully populated data.
	setStateDiags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *route53Resource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Imported id will pass through state.
	var state *route53ResourceModel
	getStateDiags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(getStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	trafficPolicyId := state.ID.ValueString()
	trafficPolicyVersions, err := r.listTrafficPolicyVersions(ctx, trafficPolicyId)
	if err != nil {
		resp.Diagnostics.AddError(
			"[API ERROR] Failed to get latest version of traffic policy: "+trafficPolicyId,
			err.Error(),
		)
		return
	}

	getTrafficPolicyResponse := &awsRoute53Client.GetTrafficPolicyOutput{}
	readTrafficPolicy := func() error {
		getTrafficPolicyResponse, err = r.client.GetTrafficPolicy(ctx, &awsRoute53Client.GetTrafficPolicyInput{
			Id: aws.String(state.ID.ValueString()),
			// Index 0 will always be the latest version of traffic policy documents.
			Version: trafficPolicyVersions.TrafficPolicies[0].Version,
		})
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

		return nil
	}

	// Retry backoff
	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second

	err = backoff.Retry(readTrafficPolicy, reconnectBackoff)
	if err != nil {
		resp.Diagnostics.AddError(
			"[API ERROR] Failed to read traffic policy",
			err.Error(),
		)
		return
	}

	// Map response body to schema and populate Computed attribute values
	state.ID = types.StringValue(*getTrafficPolicyResponse.TrafficPolicy.Id)
	state.Name = types.StringValue(*getTrafficPolicyResponse.TrafficPolicy.Name)
	state.Comment = types.StringValue(*getTrafficPolicyResponse.TrafficPolicy.Comment)
	state.Document = types.StringValue(*getTrafficPolicyResponse.TrafficPolicy.Document)
	state.Version = types.Int64Value(int64(*getTrafficPolicyResponse.TrafficPolicy.Version))

	// Set refreshed state
	setStateDiags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *route53Resource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state *route53ResourceModel
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

	updateTrafficPolicyResponse := &awsRoute53Client.CreateTrafficPolicyVersionOutput{}
	updateTrafficPolicy := func() error {
		document := plan.Document.ValueString()
		comment := plan.Comment.ValueString()
		id := state.ID.ValueString()

		var err error
		updateTrafficPolicyResponse, err = r.client.CreateTrafficPolicyVersion(ctx, &awsRoute53Client.CreateTrafficPolicyVersionInput{
			Document: aws.String(document),
			Id:       aws.String(id),
			Comment:  aws.String(comment),
		})
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
		return nil
	}

	// Retry backoff
	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second

	err := backoff.Retry(updateTrafficPolicy, reconnectBackoff)
	if err != nil {
		resp.Diagnostics.AddError(
			"[API ERROR] Failed to update traffic policy",
			err.Error(),
		)
		return
	}

	// Map response body to schema and populate Computed attribute values
	state.ID = types.StringValue(*updateTrafficPolicyResponse.TrafficPolicy.Id)
	state.Name = types.StringValue(*updateTrafficPolicyResponse.TrafficPolicy.Name)
	state.Comment = types.StringValue(*updateTrafficPolicyResponse.TrafficPolicy.Comment)
	state.Document = types.StringValue(*updateTrafficPolicyResponse.TrafficPolicy.Document)
	state.Version = types.Int64Value(int64(*updateTrafficPolicyResponse.TrafficPolicy.Version))

	setStateDiags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *route53Resource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state *route53ResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	trafficPolicyId := state.ID.ValueString()
	trafficPolicyVersions, err := r.listTrafficPolicyVersions(ctx, trafficPolicyId)
	if err != nil {
		resp.Diagnostics.AddError(
			"[API ERROR] Failed to get latest version of traffic policy "+trafficPolicyId,
			err.Error(),
		)
		return
	}

	// Retry backoff
	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second

	for _, trafficPolicy := range trafficPolicyVersions.TrafficPolicies {
		deleteTrafficPolicy := func() error {
			// Deletes Route53 traffic policy based on version
			_, err := r.client.DeleteTrafficPolicy(ctx, &awsRoute53Client.DeleteTrafficPolicyInput{
				Id:      aws.String(trafficPolicyId),
				Version: trafficPolicy.Version,
			})
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
			return nil
		}

		err := backoff.Retry(deleteTrafficPolicy, reconnectBackoff)
		if err != nil {
			resp.Diagnostics.AddError(
				fmt.Sprintf("[API ERROR] Failed to delete traffic policy version %d", trafficPolicy.Version),
				err.Error(),
			)
			return
		}
	}
}

func (r *route53Resource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *route53Resource) listTrafficPolicyVersions(ctx context.Context, trafficPolicyId string) (resp *awsRoute53Client.ListTrafficPolicyVersionsOutput, err error) {
	listTrafficPolicyVersion := func() error {
		resp, err = r.client.ListTrafficPolicyVersions(ctx, &awsRoute53Client.ListTrafficPolicyVersionsInput{
			Id: aws.String(trafficPolicyId),
		})
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
		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second
	err = backoff.Retry(listTrafficPolicyVersion, reconnectBackoff)
	return
}
