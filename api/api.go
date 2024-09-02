// Package main implements a REST API for Kite session management
package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	kitesession "github.com/nsvirk/gokitesession"
)

// Request and response structs
type (
	// TOTPRequest represents the request body for generating a TOTP value
	TOTPRequest struct {
		TOTPSecret string `json:"totp_secret"`
	}

	// LoginRequest represents the request body for user login
	LoginRequest struct {
		UserID    string `json:"user_id"`
		Password  string `json:"password"`
		TOTPValue string `json:"totp_value"`
	}

	// EnctokenRequest represents the request body for checking an enctoken
	EnctokenRequest struct {
		Enctoken string `json:"enctoken"`
	}

	// Response represents the general API response structure
	Response struct {
		Status    string      `json:"status"`
		Data      interface{} `json:"data,omitempty"`
		ErrorType string      `json:"error_type,omitempty"`
		Message   string      `json:"message,omitempty"`
	}
)

// main is the entry point of the application
func main() {
	// Initialize Echo framework
	e := echo.New()
	e.HideBanner = true

	// Middleware
	// Add logging middleware with custom format
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: "${time_rfc3339}: ip=${remote_ip}, req=${method}, uri=${uri}, status=${status}\n",
	}))
	// Add recovery middleware to handle panics
	e.Use(middleware.Recover())
	// CORS middleware
	e.Use(middleware.CORS())

	// Routes
	e.POST("/session/totp", generateTOTP)
	e.POST("/session/login", generateSession)
	e.POST("/session/valid", checkEnctoken)

	// Get port from environment variable or use default
	port := os.Getenv("KS_API_PORT")
	if port == "" {
		port = "8080"
	}

	// Start server
	fmt.Printf("Kite Session API Server v1\n")
	e.Logger.Fatal(e.Start(":" + port))
}

// generateTOTP handles the generation of TOTP values
func generateTOTP(c echo.Context) error {
	req := new(TOTPRequest)

	// Bind the request body to the TOTPRequest struct
	if err := c.Bind(req); err != nil {
		return sendErrorResponse(c, http.StatusBadRequest, "InputException", "Invalid request body")
	}

	// Validate the TOTP secret
	if req.TOTPSecret == "" {
		return sendErrorResponse(c, http.StatusBadRequest, "InputException", "totp_secret is required")
	}

	// Generate the TOTP value
	totpValue, err := kitesession.GenerateTOTPValue(req.TOTPSecret)
	if err != nil {
		return sendErrorResponse(c, http.StatusInternalServerError, "ServerException", "Failed to generate TOTP value")
	}

	// Send the successful response with the generated TOTP value
	return sendSuccessResponse(c, map[string]string{"totp_value": totpValue})
}

// generateSession handles the user login process and generates a session
func generateSession(c echo.Context) error {
	req := new(LoginRequest)
	// Bind the request body to the LoginRequest struct
	if err := c.Bind(req); err != nil {
		return sendErrorResponse(c, http.StatusBadRequest, "InputException", "Invalid request body")
	}

	// Validate the required fields
	if req.UserID == "" || req.Password == "" || req.TOTPValue == "" {
		return sendErrorResponse(c, http.StatusBadRequest, "InputException", "user_id, password, and totp_value are required")
	}

	// Generate a new session using the Kite session library
	ks := kitesession.New()
	session, err := ks.GenerateSession(req.UserID, req.Password, req.TOTPValue)
	if err != nil {
		return sendErrorResponse(c, http.StatusUnauthorized, "AuthenticationException", fmt.Sprintf("Login failed: %v", err))
	}

	// Send the successful response with the session data
	return sendSuccessResponse(c, session)
}

// checkEnctoken validates the provided enctoken
func checkEnctoken(c echo.Context) error {
	req := new(EnctokenRequest)
	// Bind the request body to the EnctokenRequest struct
	if err := c.Bind(req); err != nil {
		return sendErrorResponse(c, http.StatusBadRequest, "InputException", "Invalid request body")
	}

	// Validate the enctoken
	if req.Enctoken == "" {
		return sendErrorResponse(c, http.StatusBadRequest, "InputException", "enctoken is required")
	}

	// Check if the enctoken is valid using the Kite session library
	ks := kitesession.New()
	isValid, err := ks.CheckEnctokenValid(req.Enctoken)
	if err != nil {
		return sendErrorResponse(c, http.StatusInternalServerError, "ServerException", fmt.Sprintf("Failed to check enctoken: %v", err))
	}

	// Send the successful response with the validity status
	return sendSuccessResponse(c, map[string]bool{"is_valid": isValid})
}

// sendSuccessResponse is a helper function to send a successful JSON response
func sendSuccessResponse(c echo.Context, data interface{}) error {
	return c.JSON(http.StatusOK, Response{
		Status: "ok",
		Data:   data,
	})
}

// sendErrorResponse is a helper function to send an error JSON response
func sendErrorResponse(c echo.Context, httpStatus int, errorType, message string) error {
	return c.JSON(httpStatus, Response{
		Status:    "error",
		ErrorType: errorType,
		Message:   message,
	})
}
