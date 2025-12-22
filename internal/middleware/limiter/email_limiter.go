package limiter

import (
	"fmt"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/hanifsyahsn/go_boilerplate/internal/middleware"
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
		// 1 per second to refill (will stop refill if available token = 5), max 5 burst at a time
		limiter = rate.NewLimiter(1, 5)
		userLimiters.m[email] = limiter
	}
	return limiter
}

func RateLimitUserMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		email, exists := c.Get("email")
		if !exists {
			middleware.HandleError(c, errors.CodeUnauthorized, "Unauthorized", fmt.Errorf("email is not found in context"))
			return
		}

		limiter := getUserLimiter(email.(string))
		if !limiter.Allow() {
			middleware.HandleError(c, errors.CodeTooManyRequests, "Too many requests", fmt.Errorf("too many requests"))
			return
		}

		c.Next()
	}
}
