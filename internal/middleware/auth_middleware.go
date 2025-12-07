package middleware

import (
	"log"
	"net/http"
	"strings"

	ierr "errors"

	"github.com/gin-gonic/gin"
	"github.com/hanifsyahsn/go_boilerplate/internal/util"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/constant"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/errors"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/token"
)

const (
	authorizationHeaderKey  = "Authorization"
	authorizationTypeBearer = "Bearer"
)

func AccessAuthMiddleware(tokenMaker token.Maker) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := c.Cookie(constant.AccessTokenKey)
		if err != nil {
			log.Printf("access token cookie warning: %v", err)

			authHeader := c.GetHeader(authorizationHeaderKey)
			if authHeader == "" {
				c.AbortWithStatusJSON(
					http.StatusUnauthorized,
					util.ErrorResponse(errors.NewErrorMessage("Unauthorized", ierr.New("authorization is missing from the header"))),
				)
				return
			}

			fields := strings.Fields(authHeader)
			if len(fields) != 2 || fields[0] != authorizationTypeBearer {
				c.AbortWithStatusJSON(
					http.StatusUnauthorized,
					util.ErrorResponse(errors.NewErrorMessage("Unauthorized", ierr.New("invalid authorization header format"))),
				)
				return
			}

			tokenString = fields[1]
		}

		_, claims, err := tokenMaker.VerifyToken(tokenString)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.ErrorResponse(errors.NewErrorMessage("Unauthorized", err)))
			return
		}

		emailVal, ok := claims[constant.EmailKey]
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.ErrorResponse(errors.NewErrorMessage("Unauthorized", err)))
			return
		}
		email, ok := emailVal.(string)
		if !ok || email == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.ErrorResponse(errors.NewErrorMessage("Unauthorized", err)))
			return
		}
		c.Set(constant.EmailKey, email)

		subVal, ok := claims[constant.SubKey]
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.ErrorResponse(errors.NewErrorMessage("Unauthorized", err)))
			return
		}
		sub, ok := subVal.(float64)
		if !ok || sub == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.ErrorResponse(errors.NewErrorMessage("Unauthorized", err)))
			return
		}
		c.Set(constant.UserIdKey, int64(sub))

		c.Set(constant.AccessTokenKey, tokenString)

		c.Next()
	}
}

func RefreshAuthMiddleware(tokenMaker token.Maker) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := c.Cookie(constant.RefreshTokenKey)
		if err != nil {
			if err != nil {
				log.Printf("refresh token cookie warning: %v", err)

				authHeader := c.GetHeader(authorizationHeaderKey)
				if authHeader == "" {
					c.AbortWithStatusJSON(
						http.StatusUnauthorized,
						util.ErrorResponse(errors.NewErrorMessage("Unauthorized", ierr.New("authorization is missing from the header"))),
					)
					return
				}

				fields := strings.Fields(authHeader)
				if len(fields) != 2 || fields[0] != authorizationTypeBearer {
					c.AbortWithStatusJSON(
						http.StatusUnauthorized,
						util.ErrorResponse(errors.NewErrorMessage("Unauthorized", ierr.New("invalid authorization header format"))),
					)
					return
				}

				tokenString = fields[1]
			}
		}

		_, claims, err := tokenMaker.VerifyToken(tokenString)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.ErrorResponse(errors.NewErrorMessage("Unauthorized", err)))
			return
		}

		emailVal, ok := claims[constant.EmailKey]
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.ErrorResponse(errors.NewErrorMessage("Unauthorized", err)))
			return
		}
		email, ok := emailVal.(string)
		if !ok || email == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.ErrorResponse(errors.NewErrorMessage("Unauthorized", err)))
			return
		}
		c.Set(constant.EmailKey, email)

		subVal, ok := claims[constant.SubKey]
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.ErrorResponse(errors.NewErrorMessage("Unauthorized", err)))
			return
		}
		sub, ok := subVal.(float64)
		if !ok || sub == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.ErrorResponse(errors.NewErrorMessage("Unauthorized", err)))
			return
		}
		c.Set(constant.UserIdKey, int64(sub))

		c.Set(constant.RefreshTokenKey, tokenString)

		c.Next()
	}
}
