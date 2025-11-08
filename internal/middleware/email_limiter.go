package middleware

import (
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/hanifsyahsn/go_boilerplate/internal/util"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/errors"
	"golang.org/x/time/rate"
)

var userLimiters = struct {
	sync.Mutex
	m map[string]*rate.Limiter
}{m: make(map[string]*rate.Limiter)}

func getUserLimiter(email string) *rate.Limiter {
	userLimiters.Lock()
	defer userLimiters.Unlock()

	limiter, exists := userLimiters.m[email]
	if !exists {
		// 1 per second, 5 burst
		limiter = rate.NewLimiter(1, 5)
		userLimiters.m[email] = limiter
	}
	return limiter
}

func RateLimitUserMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		email, exists := c.Get("email")
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.ErrorResponse(errors.NewErrorMessage("Unauthorized", nil)))
			return
		}

		limiter := getUserLimiter(email.(string))
		if !limiter.Allow() {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, util.ErrorResponse(errors.NewErrorMessage("Too many requests", nil)))
			return
		}

		c.Next()
	}
}
