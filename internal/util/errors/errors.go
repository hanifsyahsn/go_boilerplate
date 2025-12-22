package errors

type Code string

const (
	CodeInternal        Code = "INTERNAL_SERVER_ERROR"
	CodeNotFound        Code = "NOT_FOUND"
	CodeConflict        Code = "CONFLICT"
	CodeUnauthorized    Code = "UNAUTHORIZED"
	CodeBadRequest      Code = "BAD_REQUEST"
	CodeTokenExpired    Code = "TOKEN_EXPIRED"
	CodeTooManyRequests Code = "TOO_MANY_REQUESTS"
)

type AppError struct {
	Code    Code
	Message string
	Err     error
}

func (e *AppError) Error() string {
	return e.Message
}

func New(code Code, message string, err error) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
		Err:     err,
	}
}
