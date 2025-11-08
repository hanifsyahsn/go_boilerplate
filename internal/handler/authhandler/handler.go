package authhandler

import (
	ierr "errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/hanifsyahsn/go_boilerplate/internal/db"
	service "github.com/hanifsyahsn/go_boilerplate/internal/service/authservice"
	"github.com/hanifsyahsn/go_boilerplate/internal/util"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/errors"
)

type Handler struct {
	store       db.Store
	userService *service.Service
}

func NewHandler(store db.Store, service *service.Service) *Handler {
	return &Handler{store: store, userService: service}
}

func (handler *Handler) Register(c *gin.Context) {
	var req service.RegisterRequest
	var err error
	if err = c.ShouldBindJSON(&req); err != nil {
		var ve validator.ValidationErrors
		if ierr.As(err, &ve) {
			uve := util.ValidatorError(ve)
			c.JSON(http.StatusBadRequest, util.ErrorResponse(errors.NewErrorMessage(uve, err)))
			return
		}
		c.JSON(http.StatusInternalServerError, util.ErrorResponse(errors.NewErrorMessage("Failed to bind JSON", err)))
		return
	}

	user, accessToken, refreshToken, err := handler.userService.RegisterService(c.Request.Context(), req)
	if err != nil {
		var e *errors.Error
		if ierr.As(err, &e) {
			c.JSON(e.ErrorCode, util.ErrorResponse(e))
			return
		}
		c.JSON(http.StatusInternalServerError, util.ErrorResponse(errors.NewErrorMessage("Failed to register user", err)))
		return
	}

	res := service.ToRegisterResponse(user, accessToken, refreshToken)

	c.JSON(http.StatusCreated, res)
}

func (handler *Handler) Login(c *gin.Context) {
	var req service.LoginRequest
	var err error
	if err = c.ShouldBindJSON(&req); err != nil {
		var ve validator.ValidationErrors
		if ierr.As(err, &ve) {
			uve := util.ValidatorError(ve)
			c.JSON(http.StatusBadRequest, util.ErrorResponse(errors.NewErrorMessage(uve, err)))
			return
		}
		c.JSON(http.StatusInternalServerError, util.ErrorResponse(errors.NewErrorMessage("Failed to bind JSON", err)))
		return
	}

	user, accessToken, refreshToken, err := handler.userService.LoginService(c.Request.Context(), req)
	if err != nil {
		var e *errors.Error
		if ierr.As(err, &e) {
			c.JSON(e.ErrorCode, util.ErrorResponse(e))
			return
		}
		c.JSON(http.StatusInternalServerError, util.ErrorResponse(errors.NewErrorMessage("Failed to login user", err)))
		return
	}

	res := service.ToLoginResponse(user, accessToken, refreshToken)

	c.JSON(http.StatusOK, res)
}

func (handler *Handler) Logout(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	fields := strings.Fields(authHeader)
	refreshToken := fields[1]

	err := handler.userService.LogoutService(c.Request.Context(), refreshToken)
	if err != nil {
		var e *errors.Error
		if ierr.As(err, &e) {
			c.JSON(e.ErrorCode, util.ErrorResponse(e))
			return
		}
		c.JSON(http.StatusInternalServerError, util.ErrorResponse(errors.NewErrorMessage("Failed to logout user", err)))
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

func (handler *Handler) RefreshAccessToken(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	fields := strings.Fields(authHeader)
	refreshToken := fields[1]

	email := c.GetString("email")

	accessToken, refreshTokenR, refreshTokenExpiration, err := handler.userService.RefreshAccessTokenService(c.Request.Context(), refreshToken, email)
	if err != nil {
		var e *errors.Error
		if ierr.As(err, &e) {
			c.JSON(e.ErrorCode, util.ErrorResponse(e))
			return
		}
		c.JSON(http.StatusInternalServerError, util.ErrorResponse(errors.NewErrorMessage("Failed to refresh access token", err)))
		return
	}

	res := service.ToRefreshTokenResponse(accessToken, refreshTokenR, refreshTokenExpiration)

	c.JSON(http.StatusCreated, res)
}
