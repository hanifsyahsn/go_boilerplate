package util

import (
	"github.com/gin-gonic/gin"
)

func ErrorResponse(err error) gin.H {
	return gin.H{"error": err.Error()}
}

func ErrorResponseWithCode(err error, code string) gin.H {
	return gin.H{
		"error": err.Error(),
		"code":  code,
	}
}
