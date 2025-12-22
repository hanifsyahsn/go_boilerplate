package auth

import (
	"fmt"
	"log"
	"strconv"
	"strings"

	ierr "errors"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hanifsyahsn/go_boilerplate/internal/middleware"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/constant"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/errors"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/redis"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/token"
)

const (
	authorizationHeaderKey  = "Authorization"
	authorizationTypeBearer = "Bearer"
)

func AccessAuthMiddleware(tokenMaker token.Maker, redis redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := c.Cookie(constant.AccessTokenKey)
		if err != nil {
			log.Printf("access token cookie warning: %v", err)

			authHeader := c.GetHeader(authorizationHeaderKey)
			if authHeader == "" {
				middleware.HandleError(c, errors.CodeUnauthorized, "Unauthorized", fmt.Errorf("authorization is missing from the header"))
				return
			}

			fields := strings.Fields(authHeader)
			if len(fields) != 2 || fields[0] != authorizationTypeBearer {
				middleware.HandleError(c, errors.CodeUnauthorized, "Unauthorized", fmt.Errorf("invalid authorization header format"))
				return
			}

			tokenString = fields[1]
		}

		_, claims, err := tokenMaker.VerifyToken(tokenString)
		if err != nil {
			if ierr.Is(err, jwt.ErrTokenExpired) {
				middleware.HandleError(c, errors.CodeTokenExpired, "Unauthorized", err)
				return
			}
			middleware.HandleError(c, errors.CodeUnauthorized, "Unauthorized", err)
			return
		}

		jtiVal, ok := claims[constant.JsonWebTokenIdKey]
		if !ok {
			middleware.HandleError(c, errors.CodeUnauthorized, "Unauthorized", fmt.Errorf("%v is not found in payload", constant.JsonWebTokenIdKey))
			return
		}
		jti, ok := jtiVal.(string)
		if !ok || jti == "" {
			middleware.HandleError(c, errors.CodeUnauthorized, "Unauthorized", fmt.Errorf("%v in payload is not a string", constant.JsonWebTokenIdKey))
			return
		}

		subVal, ok := claims[constant.SubKey]
		if !ok {
			middleware.HandleError(c, errors.CodeUnauthorized, "Unauthorized", fmt.Errorf("%v is not found in payload", constant.SubKey))
			return
		}
		sub, ok := subVal.(float64)
		if !ok || sub == 0 {
			middleware.HandleError(c, errors.CodeUnauthorized, "Unauthorized", fmt.Errorf("%v in payload is not a float64", constant.SubKey))
			return
		}

		emailVal, ok := claims[constant.EmailKey]
		if !ok {
			middleware.HandleError(c, errors.CodeUnauthorized, "Unauthorized", fmt.Errorf("%v is not found in payload", constant.EmailKey))
			return
		}
		email, ok := emailVal.(string)
		if !ok || email == "" {
			middleware.HandleError(c, errors.CodeUnauthorized, "Unauthorized", fmt.Errorf("%v in payload is not a string", constant.EmailKey))
			return
		}

		userAccessKey := "user:access:" + strconv.Itoa(int(sub))
		userJti, err := redis.Get(userAccessKey)
		if err != nil {
			middleware.HandleError(c, errors.CodeUnauthorized, "Unauthorized", err)
			return
		}
		if userJti != jti {
			middleware.HandleError(c, errors.CodeUnauthorized, "Unauthorized", fmt.Errorf("JSON web token ID in payload does not match with the stored one"))
			return
		}

		c.Set(constant.UserIdKey, int64(sub))
		c.Set(constant.JsonWebTokenIdKey, jti)
		c.Set(constant.EmailKey, email)
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
					middleware.HandleError(c, errors.CodeUnauthorized, "Unauthorized", fmt.Errorf("authorization is missing from the header"))
					return
				}

				fields := strings.Fields(authHeader)
				if len(fields) != 2 || fields[0] != authorizationTypeBearer {
					middleware.HandleError(c, errors.CodeUnauthorized, "Unauthorized", fmt.Errorf("invalid authorization header format"))
					return
				}

				tokenString = fields[1]
			}
		}

		_, claims, err := tokenMaker.VerifyToken(tokenString)
		if err != nil {
			middleware.HandleError(c, errors.CodeUnauthorized, "Unauthorized", err)
			return
		}

		emailVal, ok := claims[constant.EmailKey]
		if !ok {
			middleware.HandleError(c, errors.CodeUnauthorized, "Unauthorized", fmt.Errorf("%v is not found in payload", constant.EmailKey))
			return
		}
		email, ok := emailVal.(string)
		if !ok || email == "" {
			middleware.HandleError(c, errors.CodeUnauthorized, "Unauthorized", fmt.Errorf("%v in payload is not a string", constant.EmailKey))
			return
		}

		subVal, ok := claims[constant.SubKey]
		if !ok {
			middleware.HandleError(c, errors.CodeUnauthorized, "Unauthorized", fmt.Errorf("%v is not found in payload", constant.SubKey))
			return
		}
		sub, ok := subVal.(float64)
		if !ok || sub == 0 {
			middleware.HandleError(c, errors.CodeUnauthorized, "Unauthorized", fmt.Errorf("%v in payload is not a float64", constant.SubKey))
			return
		}

		c.Set(constant.UserIdKey, int64(sub))
		c.Set(constant.EmailKey, email)
		c.Set(constant.RefreshTokenKey, tokenString)

		c.Next()
	}
}
