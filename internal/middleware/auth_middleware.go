package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/hanifsyahsn/go_boilerplate/internal/util"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/constant"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/errors"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/token"
)

func AccessAuthMiddleware(tokenMaker token.Maker) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := c.Cookie(constant.AccessTokenKey)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.ErrorResponse(errors.NewErrorMessage("Unauthorized", err)))
			return
		}

		_, claims, err := tokenMaker.VerifyToken(tokenString)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.ErrorResponse(errors.NewErrorMessage("Unauthorized", err)))
			return
		}

		emailVal, ok := claims[constant.EmailKey]
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.ErrorResponse(errors.NewErrorMessage("Unauthorized", err)))
		}
		email, ok := emailVal.(string)
		if !ok || email == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.ErrorResponse(errors.NewErrorMessage("Unauthorized", err)))
		}
		c.Set(constant.EmailKey, email)

		subVal, ok := claims[constant.SubKey]
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.ErrorResponse(errors.NewErrorMessage("Unauthorized", err)))
		}
		sub, ok := subVal.(float64)
		if !ok || sub == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.ErrorResponse(errors.NewErrorMessage("Unauthorized", err)))
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
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.ErrorResponse(errors.NewErrorMessage("Unauthorized", err)))
			return
		}

		_, claims, err := tokenMaker.VerifyToken(tokenString)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.ErrorResponse(errors.NewErrorMessage("Unauthorized", err)))
			return
		}

		emailVal, ok := claims[constant.EmailKey]
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.ErrorResponse(errors.NewErrorMessage("Unauthorized", err)))
		}
		email, ok := emailVal.(string)
		if !ok || email == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.ErrorResponse(errors.NewErrorMessage("Unauthorized", err)))
		}
		c.Set(constant.EmailKey, email)

		subVal, ok := claims[constant.SubKey]
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.ErrorResponse(errors.NewErrorMessage("Unauthorized", err)))
		}
		sub, ok := subVal.(float64)
		if !ok || sub == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.ErrorResponse(errors.NewErrorMessage("Unauthorized", err)))
		}
		c.Set(constant.UserIdKey, int64(sub))

		c.Set(constant.RefreshTokenKey, tokenString)

		c.Next()
	}
}
