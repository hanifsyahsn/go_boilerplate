package middleware

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/errors"
)

func HandleError(c *gin.Context, code errors.Code, message string, err error) {
	if c.Writer.Written() {
		return
	}

	log.Printf(
		"[%s] %s | path=%s | err=%v",
		code,
		message,
		c.Request.URL.Path,
		err,
	)

	if code == errors.CodeTokenExpired {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": message, "code": code})
		return
	} else {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": message})
		return
	}

}
