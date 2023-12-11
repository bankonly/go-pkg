package validator

type ValidatorConfig struct {
	BadRequestMessage string
	ErrorField        string
}

var validatorConfig ValidatorConfig

func getBadRequestError() string {
	if validatorConfig.BadRequestMessage == "" {
		return "bad_request"
	}

	return validatorConfig.BadRequestMessage
}

func getErrorField() string {
	if validatorConfig.ErrorField == "" {
		return "error"
	}

	return validatorConfig.ErrorField
}

func New(cfg ValidatorConfig) {
	validatorConfig = cfg
}
