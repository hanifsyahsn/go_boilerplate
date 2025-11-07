package util

import (
	"strings"

	"github.com/go-playground/validator/v10"
)

func ValidatorError(err validator.ValidationErrors) string {
	var sb strings.Builder

	for i, e := range err {
		msg := ""
		switch e.Tag() {
		case "required":
			msg = "is required"
		case "alphanum":
			msg = "must be alphanumeric"
		case "min":
			msg = "must be at least " + e.Param() + " characters"
		case "email":
			msg = "must be a valid email"
		default:
			msg = "invalid value"
		}
		if i < len(err)-1 {
			sb.WriteString(strings.ToLower(e.Field()) + " " + msg + ", ")
		} else {
			sb.WriteString(strings.ToLower(e.Field()) + " " + msg)
		}
	}

	return sb.String()
}
