package kitesession

import (
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

// KiteSession represents the session data returned by the Kite API
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

// KiteSessionError represents an error returned by the Kite API
type KiteSessionError struct {
	ErrorCode int    `json:"error_code"`
	ErrorType string `json:"error_type"`
	Message   string `json:"message"`
}

// Error returns a string representation of the error
func (e *KiteSessionError) Error() string {
	return fmt.Sprintf("[%d] %s: %s", e.ErrorCode, e.ErrorType, e.Message)
}

// KiteSessionClient represents the client for the Kite API
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

// NewClient creates a new KiteSessionClient
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

func (c *KiteSessionClient) GenerateSession(userId, password, totpSecret, apiKey, apiSecret string) (*KiteSession, error) {
	// set client credentials
	c.UserID = userId
	c.Password = password
	c.TOTPSecret = totpSecret
	c.APIKey = apiKey
	c.APISecret = apiSecret

	if apiKey == "" || apiSecret == "" {
		return c.generateOMSSession()
	}

	return c.generateAPISession()
}

// generateOMSSession generates a session token for the OMS
func (c *KiteSessionClient) generateOMSSession() (*KiteSession, error) {

	// do login
	loginResponse, loginCookies, err := c.doOMSSessionLogin()
	if err != nil {
		return nil, err
	}

	// do twofa
	_, twofaCookies, err := c.doOMSSessionTwoFA(loginResponse.Data.RequestID)
	if err != nil {
		return nil, err
	}

	// add enctoken to client
	c.Enctoken = getStringFromAny(getCookieValue(twofaCookies, "enctoken"))

	// get user profile
	userProfile, err := c.getUserProfile()
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

// generateAPISession generates a session token for the API
func (c *KiteSessionClient) generateAPISession() (*KiteSession, error) {

	// get session id
	sessID, kfSession, err := c.getSessID()
	if err != nil {
		return nil, err
	}

	// get kf session from cookies

	// generate oms session
	omsSession, err := c.generateOMSSession()
	if err != nil {
		return nil, err
	}

	// get request token
	requestToken, err := c.getRequestToken(sessID)
	if err != nil {
		return nil, err
	}

	// generate session token
	sessionToken, err := c.generateSessionToken(requestToken)
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
