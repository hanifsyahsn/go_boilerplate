package authhandler

import (
	ierr "errors"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
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
		log.Println("Error binding JSON: ", err)
		c.JSON(http.StatusBadRequest, util.ErrorResponse(fmt.Errorf("failed to bind JSON")))
		return
	}

	user, accessToken, refreshToken, err := handler.userService.RegisterService(c.Request.Context(), req)
	var e *errors.Error
	if ierr.As(err, &e) {
		c.JSON(e.ErrorCode, util.ErrorResponse(e))
		return
	}

	res := service.ToRegisterResponse(user, accessToken, refreshToken)

	c.JSON(http.StatusCreated, res)
}

func (handler *Handler) Login(c *gin.Context) {
	var req service.LoginRequest
	var err error
	if err = c.ShouldBindJSON(&req); err != nil {
		log.Println("Error binding JSON: ", err)
		c.JSON(http.StatusBadRequest, util.ErrorResponse(fmt.Errorf("failed to bind JSON")))
		return
	}

	user, accessToken, refreshToken, err := handler.userService.LoginService(c.Request.Context(), req)
	var e *errors.Error
	if ierr.As(err, &e) {
		c.JSON(e.ErrorCode, util.ErrorResponse(e))
		return
	}

	res := service.ToLoginResponse(user, accessToken, refreshToken)

	c.JSON(http.StatusOK, res)
}
