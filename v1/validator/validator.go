package validator

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/leebenson/conform"
)

var validate *validator.Validate

func GetValidator() *validator.Validate {
	if validate == nil {
		log.Fatal("validate_not_initialized")
	}
	return validate
}

// Initialized validator instance
func NewValidator() {
	validate = validator.New(validator.WithRequiredStructEnabled())
	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get(getErrorField()), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})
}

func ValidateStruct(value interface{}) error {
	if err := conform.Strings(value); err != nil {
		return err
	}
	err := validate.Struct(value)
	if err != nil {
		validationErrors := err.(validator.ValidationErrors)
		errResult := validationErrors[0].Field()
		return errors.New(errResult)
	}
	return nil
}

// Parse validation
func Parser(body io.Reader, out interface{}) error {
	if err := json.NewDecoder(body).Decode(&out); err != nil {
		return errors.New(getBadRequestError())
	}

	if err := ValidateStruct(out); err != nil {
		return err
	}

	return nil
}
