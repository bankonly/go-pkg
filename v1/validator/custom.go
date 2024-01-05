package validator

import (
	"strings"

	"github.com/go-playground/validator/v10"
)

type Custom struct {
}

func (opts *Custom) InitCustomValidation() {
	// Enum validator
	validate.RegisterAlias("any", "enum")
	validate.RegisterValidation("enum", opts.ValidateStatusEnum)
}

func (v *Custom) ValidateStatusEnum(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	enumType := fl.Param()

	enumValues := strings.Split(enumType, "-")

	for _, v := range enumValues {
		if value == v {
			return true
		}
	}
	return false
}
