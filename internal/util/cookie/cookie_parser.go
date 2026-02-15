package cookie

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/constant"
)

func ParseTokens(c *gin.Context, accessToken, refreshToken string) {
	secure := isSecureRequest(c)
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     constant.AccessTokenKey,
		Value:    accessToken,
		Path:     "/",
		MaxAge:   60 * 30,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     constant.RefreshTokenKey,
		Value:    refreshToken,
		Path:     "/",
		MaxAge:   60 * 60 * 24 * 7,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func ParseAccessToken(c *gin.Context, accessToken string) {
	secure := isSecureRequest(c)
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     constant.AccessTokenKey,
		Value:    accessToken,
		Path:     "/",
		MaxAge:   60 * 30,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
}

func RemoveTokens(c *gin.Context) {
	secure := isSecureRequest(c)
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     constant.AccessTokenKey,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     constant.RefreshTokenKey,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func isSecureRequest(c *gin.Context) bool {
	if c.Request.TLS != nil {
		return true
	}

	if proto := c.GetHeader("X-Forwarded-Proto"); proto == "https" {
		return true
	}

	return false
}
