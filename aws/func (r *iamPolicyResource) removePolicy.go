func (r *iamPolicyResource) removePolicy(ctx context.Context, state *iamPolicyResourceModel) (unexpectedError []error) {
	var ae smithy.APIError
	var listPolicyVersionsResponse *awsIamClient.ListPolicyVersionsOutput

	removePolicy := func() error {
		for _, combinedPolicy := range state.CombinedPolicesDetail {
			policyArn, _, err := r.getPolicyArn(ctx, combinedPolicy.PolicyName.ValueString())

			if err != nil {
				unexpectedError = append(unexpectedError, err)
				continue
			}

			detachPolicyFromUserRequest := &awsIamClient.DetachUserPolicyInput{
				PolicyArn: aws.String(policyArn),
				UserName:  aws.String(state.UserName.ValueString()),
			}

			a, err := arn.Parse(policyArn)
			if err != nil {
				continue
			}
			
			listPolicyVersionsRequest := &awsIamClient.ListPolicyVersionsInput{
				PolicyArn: aws.String(policyArn),
			}

			deletePolicyRequest := &awsIamClient.DeletePolicyInput{
				PolicyArn: aws.String(policyArn),
			}

			if _, err = r.client.DetachUserPolicy(ctx, detachPolicyFromUserRequest); err != nil {
				// Ignore error where the policy is not attached
				// to the user as it is intented to detach the
				// policy from user.
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
