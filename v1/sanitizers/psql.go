package sanitizers

import (
	"strings"
)

func GetSQLErrorCode(err error) string {
	if err == nil {
		return ""
	}

	var errorCode string
	errStrs := strings.Split(err.Error(), "SQLSTATE")
	if len(errStrs) == 1 {
		return errorCode
	}
	errCode := strings.ReplaceAll(errStrs[1], ")", "")
	return strings.TrimSpace(errCode)
}
