package errors

type Error struct {
	Message   string `json:"message"`
	ErrorCode int    `json:"code"`
}

func New(message string, code int) *Error {
	return &Error{
		Message:   message,
		ErrorCode: code,
	}
}

func (e *Error) Error() string {
	return e.Message
}
