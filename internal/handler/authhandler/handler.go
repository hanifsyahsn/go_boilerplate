package authhandler

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/hanifsyahsn/go_boilerplate/internal/db"
	h "github.com/hanifsyahsn/go_boilerplate/internal/handler"
	service "github.com/hanifsyahsn/go_boilerplate/internal/service/authservice"
	"github.com/hanifsyahsn/go_boilerplate/internal/util"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/constant"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/cookie"
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
		if errors.As(err, &ve) {
			uve := util.ValidatorError(ve)
			h.HandleError(c, errors.New(uve))
			return
		}
		h.HandleError(c, err)
		return
	}

	user, accessToken, refreshToken, err := handler.userService.RegisterService(c.Request.Context(), req)
	if err != nil {
		h.HandleError(c, err)
		return
	}

	cookie.ParseTokens(c, accessToken, refreshToken)

	res := service.ToRegisterResponse(user, accessToken, refreshToken)

	c.JSON(http.StatusCreated, res)
}

func (handler *Handler) Login(c *gin.Context) {
	var req service.LoginRequest
	var err error
	if err = c.ShouldBindJSON(&req); err != nil {
		var ve validator.ValidationErrors
		if errors.As(err, &ve) {
			uve := util.ValidatorError(ve)
			h.HandleError(c, errors.New(uve))
			return
		}
		h.HandleError(c, err)
		return
	}

	user, accessToken, refreshToken, err := handler.userService.LoginService(c.Request.Context(), req)
	if err != nil {
		h.HandleError(c, err)
		return
	}

	cookie.ParseTokens(c, accessToken, refreshToken)

	res := service.ToLoginResponse(user, accessToken, refreshToken)

	c.JSON(http.StatusOK, res)
}

func (handler *Handler) Logout(c *gin.Context) {
	userId := c.GetInt64(constant.UserIdKey)
	refreshToken := c.GetString(constant.RefreshTokenKey)

	err := handler.userService.LogoutService(c.Request.Context(), refreshToken, userId)
	if err != nil {
		h.HandleError(c, err)
		return
	}

	cookie.RemoveTokens(c)

	c.JSON(http.StatusOK, gin.H{})
}

func (handler *Handler) RefreshAccessToken(c *gin.Context) {
	email := c.GetString(constant.EmailKey)
	userId := c.GetInt64(constant.UserIdKey)
	refreshToken := c.GetString(constant.RefreshTokenKey)
	jti := c.GetString(constant.JsonWebTokenIdKey)

	accessToken, _, err := handler.userService.RefreshAccessTokenService(c.Request.Context(), refreshToken, email, userId, jti)
	if err != nil {
		h.HandleError(c, err)
		return
	}

	cookie.ParseAccessToken(c, accessToken)

	res := service.ToRefreshTokenResponse(accessToken)

	c.JSON(http.StatusCreated, res)
}

func (handler *Handler) Me(c *gin.Context) {
	email := c.GetString(constant.EmailKey)

	user, err := handler.userService.MeService(c, email)
	if err != nil {
		h.HandleError(c, err)
		return
	}

	res := service.ToMeResponse(user)

	c.JSON(http.StatusOK, res)
}
