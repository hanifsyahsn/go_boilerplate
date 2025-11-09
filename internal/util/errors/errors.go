package errors

import "log"

type Error struct {
	Message   string `json:"message"`
	ErrorCode int    `json:"code"`
	Err       error  `json:"error"`
}

func New(message string, code int, err error) *Error {
	errs := &Error{
		Message:   message,
		ErrorCode: code,
		Err:       err,
	}
	log.Println(errs)
	return errs
}

func (e *Error) Error() string {
	return e.Message
}

type ErrorMessage struct {
	Message string `json:"message"`
	Err     error  `json:"error"`
}

func NewErrorMessage(message string, err error) *ErrorMessage {
	errs := &ErrorMessage{
		Message: message,
		Err:     err,
	}
	log.Println(errs)
	return errs
}

func (e *ErrorMessage) Error() string {
	return e.Message
}
