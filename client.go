package kitesession

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/net/publicsuffix"
)

const (
	loginURL   = "https://kite.zerodha.com/api/login"
	twoFAURL   = "https://kite.zerodha.com/api/twofa"
	omsURL     = "https://kite.zerodha.com/oms"
	apiURL     = "https://api.kite.trade"
	timeFormat = "2006-01-02 15:04:05"
	timeout    = 7 * time.Second
)

// User represents a Kite trading platform user
type User struct {
	UserId      string
	Password    string
	TwoFaSecret string
	APIKey      string
	APISecret   string
}

// Client handles authentication with the Kite trading platform
type Client struct {
	apiKey      string
	accessToken string
	enctoken    string
	client      *http.Client
}

// NewClient creates a new Client instance
func New(apiKey string) *Client {
	// Create a cookie jar to store cookies between requests
	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		return nil
	}
	return &Client{
		apiKey: apiKey,
		client: &http.Client{
			Timeout: timeout,
			Jar:     jar,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// SetAccessToken sets the access token
func (c *Client) SetAccessToken(accessToken string) {
	c.accessToken = accessToken
}

// SetEnctoken sets the enctoken
func (c *Client) SetEnctoken(enctoken string) {
	c.enctoken = enctoken
}

// GenerateTOTP generates a TOTP code from a secret
func (c *Client) GenerateTOTP(secret string) (string, error) {
	if len(secret) != 32 {
		return "", &KiteError{
			ErrorCode: http.StatusBadRequest,
			ErrorType: "TotpException",
			Message:   "TOTP secret is invalid",
		}
	}

	totpCode, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		return "", &KiteError{
			ErrorCode: http.StatusBadRequest,
			ErrorType: "TotpException",
			Message:   err.Error(),
		}
	}

	return totpCode, nil
}

// handleErrorResponse handles an error response from the Kite API
func (c *Client) handleErrorResponse(resp *http.Response) error {
	var kiteErr struct {
		ErrorType string `json:"error_type"`
		Message   string `json:"message"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&kiteErr); err != nil {
		return err
	}

	return &KiteError{
		ErrorCode: resp.StatusCode,
		ErrorType: kiteErr.ErrorType,
		Message:   kiteErr.Message,
	}
}
