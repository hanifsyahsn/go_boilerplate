package handler

import (
	stderrors "errors"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	appErrors "github.com/hanifsyahsn/go_boilerplate/internal/util/errors"
)

func HandleError(c *gin.Context, err error) {
	// Prevents double response when writing http response without return
	if c.Writer.Written() {
		return
	}

	var appErr *appErrors.AppError
	if stderrors.As(err, &appErr) {

		if appErr.Err != nil {
			log.Printf(
				"[%s] %s | path=%s | err=%v",
				appErr.Code,
				appErr.Message,
				c.Request.URL.Path,
				appErr.Err,
			)
		}

		c.JSON(
			appErrors.HTTPStatus(appErr.Code),
			gin.H{"message": appErr.Message},
		)
		return
	}

	log.Printf(
		"[INTERNAL_SERVER_ERROR] path=%s | err=%v",
		c.Request.URL.Path,
		err,
	)

	c.JSON(
		http.StatusInternalServerError,
		gin.H{"message": "Unexpected error"},
	)
}
