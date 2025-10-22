package aws

import (
	"errors"
	"fmt"

	"github.com/aws/smithy-go"
	"github.com/cenkalti/backoff"
	"github.com/hashicorp/terraform-plugin-framework/diag"
)

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

func addDiagnostics(diags *diag.Diagnostics, severity string, title string, errors []error, extraMessage string) {
	var combinedMessages string
	validErrors := 0

	for _, err := range errors {
		if err != nil {
			combinedMessages += fmt.Sprintf("%v\n", err)
			validErrors++
		}
	}

	if validErrors == 0 {
		return
	}

	var message string
	if extraMessage != "" {
		message = fmt.Sprintf("%s\n%s", extraMessage, combinedMessages)
	} else {
		message = combinedMessages
	}

	switch severity {
	case "warning":
		diags.AddWarning(title, message)
	case "error":
		diags.AddError(title, message)
	default:
		// Handle unknown severity if needed
	}
}
