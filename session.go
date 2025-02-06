package kitesession

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// UserSession represents the response after a successful authentication.
type UserSession struct {
	UserID       string `json:"user_id"`
	APIKey       string `json:"api_key"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Enctoken     string `json:"enctoken"`
	PublicToken  string `json:"public_token"`
	KfSession    string `json:"kf_session"`
	LoginTime    string `json:"login_time"`
	UserProfile
}

// UserProfile represents a user's personal and financial profile.
type UserProfile struct {
	UserID        string   `json:"user_id"`
	UserName      string   `json:"user_name"`
	UserShortName string   `json:"user_shortname"`
	AvatarURL     string   `json:"avatar_url"`
	UserType      string   `json:"user_type"`
	Email         string   `json:"email"`
	Broker        string   `json:"broker"`
	Meta          UserMeta `json:"meta"`
	Products      []string `json:"products"`
	OrderTypes    []string `json:"order_types"`
	Exchanges     []string `json:"exchanges"`
}

// UserMeta contains meta data of the user.
type UserMeta struct {
	DematConsent string `json:"demat_consent"`
}

// KiteError represents an error from the Kite API
type KiteError struct {
	ErrorCode int    `json:"error_code"`
	ErrorType string `json:"error_type"`
	Message   string `json:"message"`
}

// Error implements the error interface
func (e *KiteError) Error() string {
	return fmt.Sprintf("[%d] %s: %s", e.ErrorCode, e.ErrorType, e.Message)
}

// GenerateUserSession performs API-based authentication
func (c *Client) GenerateUserSession(user User) (*UserSession, error) {
	// If API key and secret are not provided, return OMS session
	if user.APIKey == "" && user.APISecret == "" {
		omsSession, err := c.getOMSSession(user)
		if err != nil {
			return nil, err
		}
		c.SetEnctoken(omsSession.Enctoken)
		return omsSession, nil
	}

	// Step 1: Get session ID
	sessID, err := c.getSessionId(user)
	if err != nil {
		return nil, err
	}

	// Step 2: Perform OMS login
	omsSession, err := c.getOMSSession(user)
	if err != nil {
		return nil, err
	}

	// Step 3: Get request token
	requestToken, err := c.getRequestToken(sessID)
	if err != nil {
		return nil, err
	}

	// Step 4: Generate checksum
	checksum := generateChecksum(c.apiKey, requestToken, user.APISecret)

	// Step 5: Generate session
	apiSession, err := c.getAPISession(checksum, requestToken)
	if err != nil {
		return nil, err
	}

	// Step 5: Set access token and enctoken
	c.SetAccessToken(apiSession.AccessToken)
	c.SetEnctoken(apiSession.Enctoken)

	// Step 6: Merge omsSession and apiSession
	apiSession.KfSession = omsSession.KfSession
	apiSession.PublicToken = omsSession.PublicToken

	return apiSession, nil
}

// getSessionId gets the session ID from the login URL
func (c *Client) getSessionId(user User) (string, error) {
	loginURL := fmt.Sprintf("https://kite.zerodha.com/connect/login?v=3&api_key=%s", user.APIKey)
	resp, err := c.client.Get(loginURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// get sess_id from header["location"]
	location := resp.Header.Get("Location")
	if location == "" {
		return "", &KiteError{
			ErrorCode: http.StatusBadRequest,
			ErrorType: "InvalidResponse",
			Message:   "Session ID not found in response",
		}
	}
	locationURL, err := url.Parse(location)
	if err != nil {
		return "", err
	}
	queryParams := locationURL.Query()
	sessID := queryParams.Get("sess_id")
	return sessID, nil
}

// getOMSSession performs OMS-based authentication
func (c *Client) getOMSSession(user User) (*UserSession, error) {
	// First login step
	data := url.Values{}
	data.Set("user_id", user.UserId)
	data.Set("password", user.Password)

	req, err := http.NewRequest("POST", loginURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp)
	}

	var loginResp struct {
		Data struct {
			RequestID string `json:"request_id"`
			TwoFAType string `json:"twofa_type"`
			Profile   struct {
				UserName      string `json:"user_name"`
				UserShortname string `json:"user_shortname"`
			} `json:"profile"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		return nil, err
	}

	// get kf_session from resp cookies
	kfSession := ""
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "kf_session" {
			kfSession = cookie.Value
		}
	}

	// Generate TOTP
	totpValue, err := c.GenerateTOTP(user.TwoFaSecret)
	if err != nil {
		return nil, err
	}

	// Second login step with TOTP
	twoFAData := url.Values{}
	twoFAData.Set("request_id", loginResp.Data.RequestID)
	twoFAData.Set("twofa_value", totpValue)
	twoFAData.Set("twofa_type", loginResp.Data.TwoFAType)
	twoFAData.Set("user_id", user.UserId)

	req, err = http.NewRequest("POST", twoFAURL, strings.NewReader(twoFAData.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err = c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp)
	}

	// Create session
	session := &UserSession{
		UserID:    user.UserId,
		KfSession: kfSession,
		LoginTime: time.Now().Format(timeFormat),
	}

	// Get public_token and enctoken from cookies
	for _, cookie := range resp.Cookies() {
		switch cookie.Name {
		case "public_token":
			session.PublicToken = cookie.Value
		case "enctoken":
			session.Enctoken = cookie.Value
		}
	}

	// Set enctoken
	c.SetEnctoken(session.Enctoken)

	return session, nil
}

// getRequestToken gets the request token from the finish URL
func (c *Client) getRequestToken(sessID string) (string, error) {
	finishURL := fmt.Sprintf("https://kite.zerodha.com/connect/finish?v=3&api_key=%s&sess_id=%s",
		c.apiKey, sessID)

	resp, err := c.client.Get(finishURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		return "", c.handleErrorResponse(resp)
	}

	location := resp.Header.Get("Location")
	if location == "" {
		return "", &KiteError{
			ErrorCode: http.StatusBadRequest,
			ErrorType: "InvalidResponse",
			Message:   "Failed to get request token",
		}
	}

	locationURL, err := url.Parse(location)
	if err != nil {
		return "", err
	}

	requestToken := locationURL.Query().Get("request_token")
	if requestToken == "" {
		return "", &KiteError{
			ErrorCode: http.StatusBadRequest,
			ErrorType: "InvalidResponse",
			Message:   "Request token not found in response",
		}
	}
	return requestToken, nil
}

// getAPISession generates a session token
func (c *Client) getAPISession(checksum, requestToken string) (*UserSession, error) {
	tokenData := url.Values{}
	tokenData.Set("api_key", c.apiKey)
	tokenData.Set("request_token", requestToken)
	tokenData.Set("checksum", checksum)

	req, err := http.NewRequest("POST", "https://api.kite.trade/session/token",
		strings.NewReader(tokenData.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp)
	}

	var sessionResp struct {
		Data *UserSession `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&sessionResp); err != nil {
		return nil, err
	}

	if sessionResp.Data == nil {
		return nil, &KiteError{
			ErrorCode: http.StatusBadRequest,
			ErrorType: "InvalidResponse",
			Message:   "Session token generation failed",
		}
	}

	return sessionResp.Data, nil
}

// IsEnctokenValid checks if the enctoken is valid
func (c *Client) IsEnctokenValid(enctoken string) bool {
	profileUrl := fmt.Sprintf("%s/user/profile", omsURL)
	req, err := http.NewRequest("GET", profileUrl, nil)
	if err != nil {
		return false
	}

	authHeader := fmt.Sprintf("enctoken %s", enctoken)
	req.Header.Add("Authorization", authHeader)
	resp, err := c.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// IsAccessTokenValid checks if the access token is valid
func (c *Client) IsAccessTokenValid(accessToken string) bool {
	profileUrl := fmt.Sprintf("%s/user/profile", apiURL)
	req, err := http.NewRequest("GET", profileUrl, nil)
	if err != nil {
		return false
	}
	authHeader := fmt.Sprintf("token %s:%s", c.apiKey, accessToken)
	req.Header.Add("Authorization", authHeader)
	resp, err := c.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

func generateChecksum(apiKey, requestToken, apiSecret string) string {
	h := sha256.New()
	h.Write([]byte(apiKey + requestToken + apiSecret))
	return hex.EncodeToString(h.Sum(nil))
}
