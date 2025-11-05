package middleware

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/hanifsyahsn/go_boilerplate/internal/util"
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
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.ErrorResponse(fmt.Errorf("unauthorized")))
			return
		}

		limiter := getUserLimiter(email.(string))
		if !limiter.Allow() {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, util.ErrorResponse(fmt.Errorf("too many requests")))
			return
		}

		c.Next()
	}
}
