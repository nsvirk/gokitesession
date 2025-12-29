package kitesession

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
)

// LoginResponse is the response from the login API
type LoginResponse struct {
	Status string `json:"status"`
	Data   struct {
		UserID      string   `json:"user_id"`
		RequestID   string   `json:"request_id"`
		TwofaType   string   `json:"twofa_type"`
		TwofaTypes  []string `json:"twofa_types"`
		TwofaStatus string   `json:"twofa_status"`
		Profile     struct {
			UserName      string `json:"user_name"`
			UserShortname string `json:"user_shortname"`
			AvatarURL     any    `json:"avatar_url"`
		} `json:"profile"`
	} `json:"data"`
}

// TwoFAResponse is the response from the twofa API
type TwoFAResponse struct {
	Status string `json:"status"`
	Data   struct {
		Profile struct {
		} `json:"profile"`
	} `json:"data"`
}

// UserProfileResponse is the response from the user profile API
type UserProfileResponse struct {
	Status string `json:"status"`
	Data   struct {
		UserID        string   `json:"user_id"`
		UserType      string   `json:"user_type"`
		Email         string   `json:"email"`
		UserName      string   `json:"user_name"`
		UserShortname string   `json:"user_shortname"`
		Broker        string   `json:"broker"`
		Exchanges     []string `json:"exchanges"`
		Products      []string `json:"products"`
		OrderTypes    []string `json:"order_types"`
		AvatarURL     any      `json:"avatar_url"`
		Meta          struct {
			DematConsent string `json:"demat_consent"`
		} `json:"meta"`
	} `json:"data"`
}

// KiteErrorResponse is the error response from the kite API
type KiteErrorResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	Data      any    `json:"data"`
	ErrorType string `json:"error_type"`
}

// doOMSSessionLogin does the login API call with context support.
// It performs the initial login step of the OMS session generation flow.
func (c *KiteSessionClient) doOMSSessionLogin(ctx context.Context) (*LoginResponse, []*http.Cookie, error) {

	// set login payload
	payload := url.Values{}
	payload.Set("user_id", c.UserID)
	payload.Set("password", c.Password)
	payload.Set("type", "user_id")

	// create login request with body
	loginRequest, err := http.NewRequest(http.MethodPost, LoginURL, strings.NewReader(payload.Encode()))
	if err != nil {
		return nil, nil, err
	}

	// add context to request
	loginRequest = loginRequest.WithContext(ctx)

	// set default headers
	for key, value := range defaultHeaders {
		loginRequest.Header.Add(key, value)
	}

	// make request
	resp, err := c.client.Do(loginRequest)
	if err != nil {
		return nil, nil, err
	}

	defer resp.Body.Close()

	// check if login is successful
	if resp.StatusCode != http.StatusOK {
		var kiteErrorResponse KiteErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&kiteErrorResponse); err != nil {
			c.KiteSessionError = &KiteSessionError{
				ErrorCode: resp.StatusCode,
				ErrorType: "DecodeException",
				Message:   fmt.Sprintf("failed to decode error response: %v", err),
			}
			return nil, nil, errors.New(c.KiteSessionError.Error())
		}
		c.KiteSessionError = &KiteSessionError{
			ErrorCode: resp.StatusCode,
			ErrorType: kiteErrorResponse.ErrorType,
			Message:   kiteErrorResponse.Message,
		}
		return nil, nil, errors.New(c.KiteSessionError.Error())
	}

	// parse response
	var loginResponse LoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&loginResponse); err != nil {
		c.KiteSessionError = &KiteSessionError{
			ErrorCode: 500,
			ErrorType: "DecodeException",
			Message:   fmt.Sprintf("failed to decode login response: %v", err),
		}
		return nil, nil, errors.New(c.KiteSessionError.Error())
	}

	return &loginResponse, resp.Cookies(), nil
}

// doOMSSessionTwoFA does the twofa API call with context support.
// It performs the two-factor authentication step of the OMS session generation flow.
func (c *KiteSessionClient) doOMSSessionTwoFA(ctx context.Context, requestID string) (*TwoFAResponse, []*http.Cookie, error) {
	// generate twofa value
	twofaValue, err := c.generateTwoFAValue()
	if err != nil {
		c.KiteSessionError = &KiteSessionError{
			ErrorCode: 400,
			ErrorType: "TOTPException",
			Message:   err.Error(),
		}
		return nil, nil, errors.New(c.KiteSessionError.Error())
	}

	// set twofa data
	payload := url.Values{}
	payload.Set("user_id", c.UserID)
	payload.Set("request_id", requestID)
	payload.Set("twofa_value", twofaValue)
	payload.Set("twofa_type", "totp")
	payload.Set("skip_session", "true")

	// make request
	twoFaRequest, err := http.NewRequest(http.MethodPost, TwoFAURL, strings.NewReader(payload.Encode()))
	if err != nil {
		return nil, nil, err
	}

	// add context to request
	twoFaRequest = twoFaRequest.WithContext(ctx)

	// add default headers
	for key, value := range defaultHeaders {
		twoFaRequest.Header.Add(key, value)
	}

	// make request
	twoFaResponse, err := c.client.Do(twoFaRequest)
	if err != nil {
		return nil, nil, err
	}

	defer twoFaResponse.Body.Close()

	// check if twofa is successful
	if twoFaResponse.StatusCode != http.StatusOK {
		var kiteErrorResponse KiteErrorResponse
		if err := json.NewDecoder(twoFaResponse.Body).Decode(&kiteErrorResponse); err != nil {
			c.KiteSessionError = &KiteSessionError{
				ErrorCode: twoFaResponse.StatusCode,
				ErrorType: "DecodeException",
				Message:   fmt.Sprintf("failed to decode error response: %v", err),
			}
			return nil, nil, errors.New(c.KiteSessionError.Error())
		}
		c.KiteSessionError = &KiteSessionError{
			ErrorCode: twoFaResponse.StatusCode,
			ErrorType: kiteErrorResponse.ErrorType,
			Message:   kiteErrorResponse.Message,
		}
		return nil, nil, errors.New(c.KiteSessionError.Error())
	}

	// parse response
	var twoFaResponseData TwoFAResponse
	if err := json.NewDecoder(twoFaResponse.Body).Decode(&twoFaResponseData); err != nil {
		c.KiteSessionError = &KiteSessionError{
			ErrorCode: 500,
			ErrorType: "DecodeException",
			Message:   fmt.Sprintf("failed to decode 2FA response: %v", err),
		}
		return nil, nil, errors.New(c.KiteSessionError.Error())
	}

	// return response and cookies
	return &twoFaResponseData, twoFaResponse.Cookies(), nil
}

// generateTwoFAValue generates the twofa value
func (c *KiteSessionClient) generateTwoFAValue() (string, error) {
	otp, err := totp.GenerateCode(c.TOTPSecret, time.Now())
	if err != nil {
		return "", err
	}
	return otp, nil
}

// getUserProfile gets the user profile with context support.
// It retrieves detailed user information after successful authentication.
func (c *KiteSessionClient) getUserProfile(ctx context.Context) (*UserProfileResponse, error) {

	// make request
	req, err := http.NewRequest(http.MethodGet, UserProfileURL, nil)
	if err != nil {
		return nil, err
	}

	// add context to request
	req = req.WithContext(ctx)

	// add default headers
	for key, value := range defaultHeaders {
		req.Header.Add(key, value)
	}

	// add authorization header
	req.Header.Add("Authorization", fmt.Sprintf("enctoken %s", c.Enctoken))

	// make request
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	// check if user profile is successful
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user profile: status code %d", resp.StatusCode)
	}

	// parse response
	var userProfileResponse UserProfileResponse
	if err := json.NewDecoder(resp.Body).Decode(&userProfileResponse); err != nil {
		return nil, fmt.Errorf("failed to decode user profile response: %w", err)
	}

	return &userProfileResponse, nil
}
