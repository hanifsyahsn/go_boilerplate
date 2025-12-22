package limiter

import (
	"fmt"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hanifsyahsn/go_boilerplate/internal/middleware"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/errors"
	"golang.org/x/time/rate"
)

var ipLimiters = struct {
	sync.Mutex
	m map[string]*rate.Limiter
}{m: make(map[string]*rate.Limiter)}

func getIpLimiter(ip string) *rate.Limiter {
	ipLimiters.Lock()
	defer ipLimiters.Unlock()

	limiter, exists := ipLimiters.m[ip]
	if !exists {
		// 5 per minute, 5 burst
		limiter = rate.NewLimiter(rate.Every(time.Minute/5), 5)
		ipLimiters.m[ip] = limiter
	}
	return limiter
}

func RateLimitIpMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()

		limiter := getIpLimiter(ip)
		if !limiter.Allow() {
			middleware.HandleError(c, errors.CodeTooManyRequests, "Too many requests", fmt.Errorf("too many requests"))
			return
		}

		c.Next()
	}
}
