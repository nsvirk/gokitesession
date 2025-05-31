package kitesession

import (
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

// doOMSSessionLogin does the login API call
func (c *KiteSessionClient) doOMSSessionLogin() (*LoginResponse, []*http.Cookie, error) {

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
		json.NewDecoder(resp.Body).Decode(&kiteErrorResponse)
		c.KiteSessionError = &KiteSessionError{
			ErrorCode: resp.StatusCode,
			ErrorType: kiteErrorResponse.ErrorType,
			Message:   kiteErrorResponse.Message,
		}
		return nil, nil, errors.New(c.KiteSessionError.Error())
	}

	// parse response
	var loginResponse LoginResponse
	json.NewDecoder(resp.Body).Decode(&loginResponse)

	return &loginResponse, resp.Cookies(), nil
}

// doOMSSessionTwoFA does the twofa API call
func (c *KiteSessionClient) doOMSSessionTwoFA(requestID string) (*TwoFAResponse, []*http.Cookie, error) {
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
		json.NewDecoder(twoFaResponse.Body).Decode(&kiteErrorResponse)
		c.KiteSessionError = &KiteSessionError{
			ErrorCode: twoFaResponse.StatusCode,
			ErrorType: kiteErrorResponse.ErrorType,
			Message:   kiteErrorResponse.Message,
		}
		return nil, nil, errors.New(c.KiteSessionError.Error())
	}

	// parse response
	var twoFaResponseData TwoFAResponse
	json.NewDecoder(twoFaResponse.Body).Decode(&twoFaResponseData)

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

// getUserProfile gets the user profile
func (c *KiteSessionClient) getUserProfile() (*UserProfileResponse, error) {

	// make request
	req, err := http.NewRequest(http.MethodGet, UserProfileURL, nil)
	if err != nil {
		return nil, err
	}

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
		return nil, errors.New("failed to get user profile")
	}

	// parse response
	var userProfileResponse UserProfileResponse
	json.NewDecoder(resp.Body).Decode(&userProfileResponse)

	return &userProfileResponse, nil
}

// getStringFromAny safely converts any to string
func getStringFromAny(v any) string {
	if v == nil {
		return ""
	}
	if str, ok := v.(string); ok {
		return str
	}
	return ""
}

// getCookieValue gets the cookie value from the cookies
func getCookieValue(cookies []*http.Cookie, name string) string {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie.Value
		}
	}
	return ""
}
