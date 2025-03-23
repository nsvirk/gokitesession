package kitesession

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
)

// Constants for Kite API URLs and headers
const (
	LoginURL         = "https://kite.zerodha.com/api/login"
	TwoFAURL         = "https://kite.zerodha.com/api/twofa"
	OMSURL           = "https://kite.zerodha.com/oms"
	APIURL           = "https://api.kite.trade"
	ConnectLoginURL  = "https://kite.zerodha.com/connect/login"
	ConnectFinishURL = "https://kite.zerodha.com/connect/finish"
	SessionTokenURL  = "https://api.kite.trade/session/token"
	TimeFormat       = "2006-01-02 15:04:05"
	Timezone         = "Asia/Kolkata"
	Timeout          = 7 * time.Second
)

// Default headers for requests
var defaultHeaders = map[string]string{
	"user-agent":     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
	"content-type":   "application/x-www-form-urlencoded",
	"x-kite-version": "3.0.0",
}

// KiteSession represents authentication tokens and user profile
type KiteSession struct {
	UserID        string                 `json:"user_id"`
	UserName      string                 `json:"user_name,omitempty"`
	UserShortname string                 `json:"user_shortname,omitempty"`
	PublicToken   string                 `json:"public_token,omitempty"`
	KFSession     string                 `json:"kf_session,omitempty"`
	Enctoken      string                 `json:"enctoken,omitempty"`
	LoginTime     string                 `json:"login_time,omitempty"`
	UserType      string                 `json:"user_type,omitempty"`
	Email         string                 `json:"email,omitempty"`
	Broker        string                 `json:"broker,omitempty"`
	Exchanges     []string               `json:"exchanges,omitempty"`
	Products      []string               `json:"products,omitempty"`
	OrderTypes    []string               `json:"order_types,omitempty"`
	AvatarURL     string                 `json:"avatar_url,omitempty"`
	APIKey        string                 `json:"api_key,omitempty"`
	AccessToken   string                 `json:"access_token,omitempty"`
	RefreshToken  string                 `json:"refresh_token,omitempty"`
	Meta          map[string]interface{} `json:"meta,omitempty"`
}

// KiteError represents Kite API errors
type KiteError struct {
	ErrorCode int    `json:"error_code"`
	ErrorType string `json:"error_type"`
	Message   string `json:"message"`
}

func (e *KiteError) Error() string {
	return fmt.Sprintf("[%d] %s: %s", e.ErrorCode, e.ErrorType, e.Message)
}

// KiteSessionClient handles Kite session generation and validation
type KiteSessionClient struct {
	client *http.Client
}

// NewKiteSessionClient creates a new KiteSessionClient instance
func NewKiteSessionClient() (*KiteSessionClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Jar:     jar,
		Timeout: Timeout,
	}

	return &KiteSessionClient{
		client: client,
	}, nil
}

// GenerateSession generates a new session for the given user
func (k *KiteSessionClient) GenerateSession(userID, password, totpSecret, apiKey, apiSecret string) (*KiteSession, error) {
	var sessionData map[string]interface{}
	var err error

	if apiKey != "" && apiSecret != "" {
		// Use API-based authentication flow
		sessionData, err = k.generateAPISession(userID, password, totpSecret, apiKey, apiSecret)
	} else {
		// Use OMS (web) flow
		sessionData, err = k.generateOMSSession(userID, password, totpSecret)
	}

	if err != nil {
		return nil, err
	}

	// Convert map to KiteSession struct
	sessionBytes, err := json.Marshal(sessionData)
	if err != nil {
		return nil, &KiteError{
			ErrorCode: 500,
			ErrorType: "InternalError",
			Message:   "Failed to process session data: " + err.Error(),
		}
	}

	var session KiteSession
	if err := json.Unmarshal(sessionBytes, &session); err != nil {
		return nil, &KiteError{
			ErrorCode: 500,
			ErrorType: "InternalError",
			Message:   "Failed to process session data: " + err.Error(),
		}
	}

	return &session, nil
}

// generateOMSSession performs login to Kite platform with two-factor authentication
func (k *KiteSessionClient) generateOMSSession(userID, password, totpSecret string) (map[string]interface{}, error) {
	// Step 1: Make login request
	loginHeader := make(http.Header)
	for key, value := range defaultHeaders {
		loginHeader.Set(key, value)
	}
	loginHeader.Set("x-kite-userid", userID)

	loginData := url.Values{}
	loginData.Set("user_id", userID)
	loginData.Set("password", password)
	loginData.Set("type", "user_id")

	loginReq, err := http.NewRequest("POST", LoginURL, strings.NewReader(loginData.Encode()))
	if err != nil {
		return nil, &KiteError{
			ErrorCode: 500,
			ErrorType: "InternalError",
			Message:   "Failed to create login request: " + err.Error(),
		}
	}
	loginReq.Header = loginHeader

	loginResp, err := k.client.Do(loginReq)
	if err != nil {
		return nil, &KiteError{
			ErrorCode: 500,
			ErrorType: "NetworkError",
			Message:   "Network error while connecting to Kite: " + err.Error(),
		}
	}
	defer loginResp.Body.Close()

	if loginResp.StatusCode != 200 {
		return nil, k.handleErrorResponse(loginResp)
	}

	// Get kf_session from cookies
	var kfSession string
	for _, cookie := range loginResp.Cookies() {
		if cookie.Name == "kf_session" {
			kfSession = cookie.Value
			break
		}
	}

	// Parse login response
	var loginResponseData struct {
		Status string `json:"status"`
		Data   struct {
			RequestID string `json:"request_id"`
			TwoFAType string `json:"twofa_type"`
		} `json:"data"`
	}

	body, err := io.ReadAll(loginResp.Body)
	if err != nil {
		return nil, &KiteError{
			ErrorCode: 500,
			ErrorType: "InternalError",
			Message:   "Failed to read login response: " + err.Error(),
		}
	}

	if err := json.Unmarshal(body, &loginResponseData); err != nil {
		return nil, &KiteError{
			ErrorCode: 400,
			ErrorType: "InvalidResponse",
			Message:   "Invalid response from Kite API: " + err.Error(),
		}
	}

	if loginResponseData.Status != "success" {
		return nil, &KiteError{
			ErrorCode: 400,
			ErrorType: "LoginFailed",
			Message:   "Login failed",
		}
	}

	// Step 2: Make 2FA request
	requestID := loginResponseData.Data.RequestID
	twoFAType := loginResponseData.Data.TwoFAType

	// Generate TOTP value
	totpValue, err := k.generateTOTP(totpSecret)
	if err != nil {
		return nil, err
	}

	// Make 2FA request
	twoFAData := url.Values{}
	twoFAData.Set("request_id", requestID)
	twoFAData.Set("twofa_value", totpValue)
	twoFAData.Set("twofa_type", twoFAType)
	twoFAData.Set("user_id", userID)

	twoFAReq, err := http.NewRequest("POST", TwoFAURL, strings.NewReader(twoFAData.Encode()))
	if err != nil {
		return nil, &KiteError{
			ErrorCode: 500,
			ErrorType: "InternalError",
			Message:   "Failed to create 2FA request: " + err.Error(),
		}
	}
	for key, value := range defaultHeaders {
		twoFAReq.Header.Set(key, value)
	}

	twoFAResp, err := k.client.Do(twoFAReq)
	if err != nil {
		return nil, &KiteError{
			ErrorCode: 500,
			ErrorType: "NetworkError",
			Message:   "Network error while connecting to Kite: " + err.Error(),
		}
	}
	defer twoFAResp.Body.Close()

	if twoFAResp.StatusCode != 200 {
		return nil, k.handleErrorResponse(twoFAResp)
	}

	loginTime := time.Now().Format(TimeFormat)

	// Get data from cookies
	var publicToken, enctoken string
	for _, cookie := range twoFAResp.Cookies() {
		switch cookie.Name {
		case "public_token":
			publicToken = cookie.Value
		case "enctoken":
			enctoken = cookie.Value
		}
	}

	if enctoken == "" {
		return nil, &KiteError{
			ErrorCode: 400,
			ErrorType: "InvalidResponse",
			Message:   "Failed to get enctoken from response",
		}
	}

	// Get user profile data
	profileData, err := k.fetchUserProfile(enctoken)
	if err != nil {
		return nil, err
	}

	sessionData := map[string]interface{}{
		"user_id":        userID,
		"user_name":      profileData["user_name"],
		"user_shortname": profileData["user_shortname"],
		"public_token":   publicToken,
		"kf_session":     kfSession,
		"enctoken":       enctoken,
		"login_time":     loginTime,
		"user_type":      profileData["user_type"],
		"email":          profileData["email"],
		"broker":         profileData["broker"],
		"exchanges":      profileData["exchanges"],
		"products":       profileData["products"],
		"order_types":    profileData["order_types"],
		"avatar_url":     profileData["avatar_url"],
		"meta":           profileData["meta"],
	}

	return sessionData, nil
}

// fetchUserProfile fetches user profile information using enctoken
func (k *KiteSessionClient) fetchUserProfile(enctoken string) (map[string]interface{}, error) {
	profileURL := OMSURL + "/user/profile"
	profileReq, err := http.NewRequest("GET", profileURL, nil)
	if err != nil {
		return nil, &KiteError{
			ErrorCode: 500,
			ErrorType: "InternalError",
			Message:   "Failed to create profile request: " + err.Error(),
		}
	}
	profileReq.Header.Set("Authorization", "enctoken "+enctoken)

	profileResp, err := k.client.Do(profileReq)
	if err != nil {
		return nil, &KiteError{
			ErrorCode: 500,
			ErrorType: "NetworkError",
			Message:   "Network error while connecting to Kite: " + err.Error(),
		}
	}
	defer profileResp.Body.Close()

	if profileResp.StatusCode != 200 {
		return nil, k.handleErrorResponse(profileResp)
	}

	var profileResponseData struct {
		Status string                 `json:"status"`
		Data   map[string]interface{} `json:"data"`
	}

	body, err := io.ReadAll(profileResp.Body)
	if err != nil {
		return nil, &KiteError{
			ErrorCode: 500,
			ErrorType: "InternalError",
			Message:   "Failed to read profile response: " + err.Error(),
		}
	}

	if err := json.Unmarshal(body, &profileResponseData); err != nil {
		return nil, &KiteError{
			ErrorCode: 400,
			ErrorType: "InvalidResponse",
			Message:   "Invalid profile response from Kite API: " + err.Error(),
		}
	}

	if profileResponseData.Status != "success" {
		return nil, &KiteError{
			ErrorCode: 400,
			ErrorType: "InvalidResponse",
			Message:   "Failed to fetch user profile data",
		}
	}

	return profileResponseData.Data, nil
}

// generateAPISession performs API-based login to Kite platform
func (k *KiteSessionClient) generateAPISession(userID, password, totpSecret, apiKey, apiSecret string) (map[string]interface{}, error) {
	// Step 1: Get sess_id from login page
	loginURL := fmt.Sprintf("%s?v=3&api_key=%s", ConnectLoginURL, apiKey)

	loginReq, err := http.NewRequest("GET", loginURL, nil)
	if err != nil {
		return nil, &KiteError{
			ErrorCode: 500,
			ErrorType: "InternalError",
			Message:   "Failed to create login request: " + err.Error(),
		}
	}

	// Disable automatic redirect
	client := &http.Client{
		Jar:     k.client.Jar,
		Timeout: Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	loginResp, err := client.Do(loginReq)
	if err != nil {
		return nil, &KiteError{
			ErrorCode: 500,
			ErrorType: "NetworkError",
			Message:   "Network error while connecting to Kite: " + err.Error(),
		}
	}
	defer loginResp.Body.Close()

	if loginResp.StatusCode != 302 {
		return nil, k.handleErrorResponse(loginResp)
	}

	location := loginResp.Header.Get("Location")
	if location == "" {
		return nil, &KiteError{
			ErrorCode: 400,
			ErrorType: "InvalidResponse",
			Message:   "Failed to get session ID from login page",
		}
	}

	locationURL, err := url.Parse(location)
	if err != nil {
		return nil, &KiteError{
			ErrorCode: 500,
			ErrorType: "InternalError",
			Message:   "Failed to parse location URL: " + err.Error(),
		}
	}

	query := locationURL.Query()
	sessID := query.Get("sess_id")
	if sessID == "" {
		return nil, &KiteError{
			ErrorCode: 400,
			ErrorType: "InvalidResponse",
			Message:   "Session ID not found in response",
		}
	}

	// Get kf_session from cookies
	var kfSession string
	for _, cookie := range loginResp.Cookies() {
		if cookie.Name == "kf_session" {
			kfSession = cookie.Value
			break
		}
	}

	if kfSession == "" {
		return nil, &KiteError{
			ErrorCode: 400,
			ErrorType: "InvalidResponse",
			Message:   "KF Session not found in response",
		}
	}

	// Step 2: Do OMS Login with credentials
	_, err = k.generateOMSSession(userID, password, totpSecret)
	if err != nil {
		return nil, err
	}

	// Step 3: Get request token
	finishURL := fmt.Sprintf("%s?v=3&api_key=%s&sess_id=%s", ConnectFinishURL, apiKey, sessID)

	finishReq, err := http.NewRequest("GET", finishURL, nil)
	if err != nil {
		return nil, &KiteError{
			ErrorCode: 500,
			ErrorType: "InternalError",
			Message:   "Failed to create finish request: " + err.Error(),
		}
	}

	finishResp, err := client.Do(finishReq)
	if err != nil {
		return nil, &KiteError{
			ErrorCode: 500,
			ErrorType: "NetworkError",
			Message:   "Network error while connecting to Kite: " + err.Error(),
		}
	}
	defer finishResp.Body.Close()

	if finishResp.StatusCode != 302 {
		return nil, k.handleErrorResponse(finishResp)
	}

	location = finishResp.Header.Get("Location")
	if location == "" {
		return nil, &KiteError{
			ErrorCode: 400,
			ErrorType: "InvalidResponse",
			Message:   "Failed to get request token",
		}
	}

	locationURL, err = url.Parse(location)
	if err != nil {
		return nil, &KiteError{
			ErrorCode: 500,
			ErrorType: "InternalError",
			Message:   "Failed to parse location URL: " + err.Error(),
		}
	}

	query = locationURL.Query()
	requestToken := query.Get("request_token")
	if requestToken == "" {
		return nil, &KiteError{
			ErrorCode: 400,
			ErrorType: "InvalidResponse",
			Message:   "Request token not found in response",
		}
	}

	// Step 4: Generate session token
	checksum := generateChecksum(apiKey, requestToken, apiSecret)

	payload := url.Values{}
	payload.Set("api_key", apiKey)
	payload.Set("request_token", requestToken)
	payload.Set("checksum", checksum)

	tokenReq, err := http.NewRequest("POST", SessionTokenURL, strings.NewReader(payload.Encode()))
	if err != nil {
		return nil, &KiteError{
			ErrorCode: 500,
			ErrorType: "InternalError",
			Message:   "Failed to create token request: " + err.Error(),
		}
	}

	for key, value := range defaultHeaders {
		tokenReq.Header.Set(key, value)
	}

	tokenResp, err := k.client.Do(tokenReq)
	if err != nil {
		return nil, &KiteError{
			ErrorCode: 500,
			ErrorType: "NetworkError",
			Message:   "Network error while connecting to Kite: " + err.Error(),
		}
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != 200 {
		return nil, k.handleErrorResponse(tokenResp)
	}

	var tokenResponseData struct {
		Status string                 `json:"status"`
		Data   map[string]interface{} `json:"data"`
	}

	body, err := io.ReadAll(tokenResp.Body)
	if err != nil {
		return nil, &KiteError{
			ErrorCode: 500,
			ErrorType: "InternalError",
			Message:   "Failed to read token response: " + err.Error(),
		}
	}

	if err := json.Unmarshal(body, &tokenResponseData); err != nil {
		return nil, &KiteError{
			ErrorCode: 400,
			ErrorType: "InvalidResponse",
			Message:   "Invalid token response from Kite API: " + err.Error(),
		}
	}

	if tokenResponseData.Status != "success" {
		return nil, &KiteError{
			ErrorCode: 400,
			ErrorType: "InvalidResponse",
			Message:   "Session token generation failed",
		}
	}

	apiSession := tokenResponseData.Data
	apiSession["kf_session"] = kfSession

	return apiSession, nil
}

// generateChecksum generates checksum for API authentication
func generateChecksum(apiKey, requestToken, apiSecret string) string {
	data := apiKey + requestToken + apiSecret
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// generateTOTP generates TOTP for two-factor authentication
func (k *KiteSessionClient) generateTOTP(totpSecret string) (string, error) {
	if len(totpSecret) != 32 {
		return "", &KiteError{
			ErrorCode: 400,
			ErrorType: "TotpException",
			Message:   "Invalid TOTP secret: must be 32 characters long",
		}
	}

	otp, err := totp.GenerateCode(totpSecret, time.Now())
	if err != nil {
		return "", &KiteError{
			ErrorCode: 400,
			ErrorType: "TotpException",
			Message:   "TOTP generation failed: " + err.Error(),
		}
	}

	return otp, nil
}

// IsValidEnctoken validates if the enctoken is still valid
func (k *KiteSessionClient) IsValidEnctoken(enctoken string) bool {
	if enctoken == "" {
		return false
	}

	profileURL := OMSURL + "/user/profile"
	req, err := http.NewRequest("GET", profileURL, nil)
	if err != nil {
		return false
	}

	req.Header.Set("Authorization", "enctoken "+enctoken)

	resp, err := k.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
}

// IsValidAccessToken validates if the access_token is still valid
func (k *KiteSessionClient) IsValidAccessToken(apiKey, accessToken string) bool {
	if accessToken == "" {
		return false
	}

	profileURL := APIURL + "/user/profile"
	req, err := http.NewRequest("GET", profileURL, nil)
	if err != nil {
		return false
	}

	req.Header.Set("Authorization", "token "+apiKey+":"+accessToken)

	resp, err := k.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
}

// handleErrorResponse handles error responses from Kite API
func (k *KiteSessionClient) handleErrorResponse(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &KiteError{
			ErrorCode: 500,
			ErrorType: "InternalError",
			Message:   "Failed to read error response: " + err.Error(),
		}
	}

	var errorData struct {
		Status    string `json:"status"`
		ErrorType string `json:"error_type"`
		Message   string `json:"message"`
	}

	if err := json.Unmarshal(body, &errorData); err != nil {
		// If response is not JSON, use status code and text
		return &KiteError{
			ErrorCode: resp.StatusCode,
			ErrorType: "ParseError",
			Message:   "Failed to parse error response: " + string(body),
		}
	}

	return &KiteError{
		ErrorCode: resp.StatusCode,
		ErrorType: errorData.ErrorType,
		Message:   errorData.Message,
	}
}
