package errors

import "log"

type Error struct {
	Message   string `json:"message"`
	ErrorCode int    `json:"code"`
}

func New(message string, code int, err error) *Error {
	log.Println(message)
	log.Println(err)
	return &Error{
		Message:   message,
		ErrorCode: code,
	}
}

func (e *Error) Error() string {
	return e.Message
}

type ErrorMessage struct {
	Message string `json:"message"`
}

func NewErrorMessage(message string, err error) *ErrorMessage {
	log.Println(message)
	log.Println(err)
	return &ErrorMessage{
		Message: message,
	}
}

func (e *ErrorMessage) Error() string {
	return e.Message
}
