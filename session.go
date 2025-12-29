// Package kitesession provides automated session token generation for Zerodha Kite API.
//
// This package handles the complete authentication flow including login, 2FA (TOTP),
// and session token generation for both OMS and API sessions.
//
// Example usage with context:
//
//	client, err := kitesession.NewClient()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//
//	session, err := client.GenerateSession(
//	    ctx, userId, password, totpSecret, apiKey, apiSecret,
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	fmt.Printf("Access Token: %s\n", session.AccessToken)
package kitesession

import (
	"context"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"time"
)

// Constants for Kite API URLs and headers
const (
	LoginURL         = "https://kite.zerodha.com/api/login"
	TwoFAURL         = "https://kite.zerodha.com/api/twofa"
	APIURL           = "https://api.kite.trade"
	ConnectLoginURL  = "https://kite.zerodha.com/connect/login"
	ConnectFinishURL = "https://kite.zerodha.com/connect/finish"
	SessionTokenURL  = "https://api.kite.trade/session/token"
	UserProfileURL   = "https://kite.zerodha.com/oms/user/profile"
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

// KiteSession represents the session data returned by the Kite API.
// It contains authentication tokens, user profile information, and trading permissions.
type KiteSession struct {
	UserID        string         `json:"user_id"`
	UserName      string         `json:"user_name,omitempty"`
	UserShortname string         `json:"user_shortname,omitempty"`
	PublicToken   string         `json:"public_token,omitempty"`
	KFSession     string         `json:"kf_session,omitempty"`
	Enctoken      string         `json:"enctoken,omitempty"`
	LoginTime     string         `json:"login_time,omitempty"`
	UserType      string         `json:"user_type,omitempty"`
	Email         string         `json:"email,omitempty"`
	Broker        string         `json:"broker,omitempty"`
	Exchanges     []string       `json:"exchanges,omitempty"`
	Products      []string       `json:"products,omitempty"`
	OrderTypes    []string       `json:"order_types,omitempty"`
	AvatarURL     string         `json:"avatar_url,omitempty"`
	APIKey        string         `json:"api_key,omitempty"`
	AccessToken   string         `json:"access_token,omitempty"`
	RefreshToken  string         `json:"refresh_token,omitempty"`
	Meta          map[string]any `json:"meta,omitempty"`
}

// KiteSessionError represents an error returned by the Kite API.
// It includes the error code, type, and a descriptive message.
type KiteSessionError struct {
	ErrorCode int    `json:"error_code"`
	ErrorType string `json:"error_type"`
	Message   string `json:"message"`
}

// Error returns a string representation of the error.
// It implements the error interface.
func (e *KiteSessionError) Error() string {
	return fmt.Sprintf("[%d] %s: %s", e.ErrorCode, e.ErrorType, e.Message)
}

// KiteSessionClient represents the client for the Kite API.
// It manages HTTP connections, session state, and authentication credentials.
type KiteSessionClient struct {
	UserID           string
	Password         string
	TOTPSecret       string
	APIKey           string
	APISecret        string
	Enctoken         string
	AccessToken      string
	KiteSessionError *KiteSessionError
	client           *http.Client
}

// NewClient creates a new KiteSessionClient with default configuration.
// It initializes an HTTP client with cookie jar support and appropriate timeout settings.
func NewClient() (*KiteSessionClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	client := &KiteSessionClient{
		client: &http.Client{
			Jar:     jar,
			Timeout: Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	return client, nil
}

// GenerateSession generates a Kite session with context support.
//
// The context allows you to control timeouts and cancellation for the authentication flow.
//
// If apiKey and apiSecret are provided, it generates an API session (with access_token).
// If apiKey and apiSecret are empty, it generates an OMS session (with enctoken only).
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - userId: Kite user ID
//   - password: Kite password
//   - totpSecret: TOTP secret for 2FA authentication
//   - apiKey: API key (optional, leave empty for OMS session)
//   - apiSecret: API secret (optional, leave empty for OMS session)
//
// Returns:
//   - *KiteSession: Session data including tokens and user profile
//   - error: Error if session generation fails
func (c *KiteSessionClient) GenerateSession(ctx context.Context, userId, password, totpSecret, apiKey, apiSecret string) (*KiteSession, error) {
	// set client credentials
	c.UserID = userId
	c.Password = password
	c.TOTPSecret = totpSecret
	c.APIKey = apiKey
	c.APISecret = apiSecret

	if apiKey == "" || apiSecret == "" {
		return c.generateOMSSession(ctx)
	}

	return c.generateAPISession(ctx)
}

// generateOMSSession generates a session token for the OMS with context support.
// It performs the complete OMS authentication flow: login, 2FA, and profile retrieval.
func (c *KiteSessionClient) generateOMSSession(ctx context.Context) (*KiteSession, error) {

	// do login
	loginResponse, loginCookies, err := c.doOMSSessionLogin(ctx)
	if err != nil {
		return nil, err
	}

	// do twofa
	_, twofaCookies, err := c.doOMSSessionTwoFA(ctx, loginResponse.Data.RequestID)
	if err != nil {
		return nil, err
	}

	// add enctoken to client
	c.Enctoken = getStringFromAny(getCookieValue(twofaCookies, "enctoken"))

	// get user profile
	userProfile, err := c.getUserProfile(ctx)
	if err != nil {
		return nil, err
	}

	// generate session
	kiteSession := KiteSession{
		UserID:        getStringFromAny(loginResponse.Data.UserID),
		UserName:      getStringFromAny(loginResponse.Data.Profile.UserName),
		UserShortname: getStringFromAny(loginResponse.Data.Profile.UserShortname),
		AvatarURL:     getStringFromAny(loginResponse.Data.Profile.AvatarURL),
		PublicToken:   getStringFromAny(getCookieValue(twofaCookies, "public_token")),
		KFSession:     getStringFromAny(getCookieValue(loginCookies, "kf_session")),
		Enctoken:      getStringFromAny(getCookieValue(twofaCookies, "enctoken")),
		LoginTime:     time.Now().Format(TimeFormat),
		UserType:      userProfile.Data.UserType,
		Email:         userProfile.Data.Email,
		Broker:        userProfile.Data.Broker,
		Exchanges:     userProfile.Data.Exchanges,
		Products:      userProfile.Data.Products,
		OrderTypes:    userProfile.Data.OrderTypes,
		Meta: map[string]any{
			"demat_consent": userProfile.Data.Meta.DematConsent,
		},
	}

	return &kiteSession, nil
}

// generateAPISession generates a session token for the API with context support.
// It performs the complete API authentication flow: session ID, OMS session, request token,
// and session token generation.
func (c *KiteSessionClient) generateAPISession(ctx context.Context) (*KiteSession, error) {

	// get session id
	sessID, kfSession, err := c.getSessID(ctx)
	if err != nil {
		return nil, err
	}

	// generate oms session
	omsSession, err := c.generateOMSSession(ctx)
	if err != nil {
		return nil, err
	}

	// get request token
	requestToken, err := c.getRequestToken(ctx, sessID)
	if err != nil {
		return nil, err
	}

	// generate session token
	sessionToken, err := c.generateSessionToken(ctx, requestToken)
	if err != nil {
		return nil, err
	}
	apiSession := sessionToken.Data

	// add access token to client
	c.AccessToken = apiSession.AccessToken

	// make kite session
	kiteSession := KiteSession{
		UserID:        omsSession.UserID,
		UserName:      omsSession.UserName,
		UserShortname: omsSession.UserShortname,
		AvatarURL:     omsSession.AvatarURL,
		PublicToken:   omsSession.PublicToken,
		KFSession:     kfSession,
		Enctoken:      sessionToken.Data.Enctoken,
		LoginTime:     apiSession.LoginTime,
		UserType:      apiSession.UserType,
		Email:         apiSession.Email,
		Broker:        apiSession.Broker,
		Exchanges:     apiSession.Exchanges,
		Products:      apiSession.Products,
		OrderTypes:    apiSession.OrderTypes,
		Meta: map[string]any{
			"demat_consent": apiSession.Meta.DematConsent,
		},
		APIKey:       apiSession.APIKey,
		AccessToken:  apiSession.AccessToken,
		RefreshToken: apiSession.RefreshToken,
	}

	return &kiteSession, nil

}

// getStringFromAny safely converts any type to string.
// Returns empty string if the value is nil or cannot be converted to string.
func getStringFromAny(v any) string {
	if v == nil {
		return ""
	}
	if str, ok := v.(string); ok {
		return str
	}
	return ""
}

// getCookieValue retrieves the value of a cookie by name from a slice of cookies.
// Returns empty string if the cookie is not found.
func getCookieValue(cookies []*http.Cookie, name string) string {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie.Value
		}
	}
	return ""
}
