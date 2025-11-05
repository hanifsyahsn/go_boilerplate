package middleware

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/hanifsyahsn/go_boilerplate/internal/util"
)

func AuthMiddleware(tokenMaker *util.TokenMaker) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			log.Println("Authorization header is missing")
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.ErrorResponse(fmt.Errorf("unauthorized")))
			return
		}

		fields := strings.Fields(authHeader)
		if len(fields) != 2 || strings.ToLower(fields[0]) != "bearer" {
			log.Println("Invalid authorization header format")
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.ErrorResponse(fmt.Errorf("unauthorized")))
			return
		}

		tokenString := fields[1]

		_, claims, err := tokenMaker.VerifyToken(tokenString)
		if err != nil {
			log.Println("invalid or expired token")
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.ErrorResponse(fmt.Errorf("unauthorized")))
			return
		}

		email, ok := claims["email"].(string)
		if !ok {
			log.Println("invalid email claims")
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.ErrorResponse(fmt.Errorf("unauthorized")))
			return
		}

		c.Set("email", email)

		c.Next()
	}
}
