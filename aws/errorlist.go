package aws

const (
	ERR_INTERNAL_ERROR  = "InternalFailure"
	ERR_REQ_EXPIRED     = "RequestExpired"
	ERR_SERVICE_UNAVAIL = "ServiceUnavailable"
	ERR_THROTTLING      = "ThrottlingException"
)

func isAbleToRetry(errCode string) bool {
	switch errCode {
	case
		// ERR_INTERNAL_ERROR,
		// ERR_REQ_EXPIRED,
		// ERR_SERVICE_UNAVAIL,
		ERR_THROTTLING:
		return true
	default:
		return false
	}
	// return false
}
