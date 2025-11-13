package middleware

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/hanifsyahsn/go_boilerplate/internal/util"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/errors"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/token"
)

const (
	authorizationHeaderKey  = "Authorization"
	authorizationTypeBearer = "Bearer"
)

func AuthMiddleware(tokenMaker token.Maker) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader(authorizationHeaderKey)
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.ErrorResponse(errors.NewErrorMessage("Unauthorized", fmt.Errorf("authorization header is missing"))))
			return
		}

		fields := strings.Fields(authHeader)
		if len(fields) != 2 || fields[0] != authorizationTypeBearer {
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.ErrorResponse(errors.NewErrorMessage("Unauthorized", fmt.Errorf("unsupported authorization type"))))
			return
		}

		tokenString := fields[1]

		_, claims, err := tokenMaker.VerifyToken(tokenString)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.ErrorResponse(errors.NewErrorMessage("Unauthorized", err)))
			return
		}

		fmt.Println(reflect.TypeOf(claims["sub"]))

		email := claims["email"].(string)
		c.Set("email", email)
		if uid, ok := claims["sub"].(float64); ok {
			c.Set("user_id", int64(uid))
		}

		c.Next()
	}
}
