package stacktrace

import "errors"

var (
	MatchString = "StackTraceErr01"
)

func BadRequest(message string) error {
	return errors.New("400" + MatchString + message)
}

func Unauthorized(message string) error {
	return errors.New("401" + MatchString + message)
}

func InternalServerError(message string) error {
	return errors.New("401" + MatchString + message)
}
