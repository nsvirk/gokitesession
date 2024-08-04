// Package kitesession provides functionality to interact with the Kite API.
package kitesession

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	requestTimeout = 7 * time.Second
	userAgent      = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
	contentType    = "application/x-www-form-urlencoded"
	accept         = "application/json"
	defaultBaseURI = "https://kite.zerodha.com"
	uriLogin       = "/api/login"
	uriTwofa       = "/api/twofa"
	uriUserProfile = "/oms/user/profile"
)

// Session represents the Kite session data.
type Session struct {
	UserID        string `json:"user_id"`
	Username      string `json:"user_name"`
	UserShortname string `json:"user_shortname"`
	AvatarURL     string `json:"avatar_url"`
	PublicToken   string `json:"public_token"`
	KFSession     string `json:"kf_session"`
	Enctoken      string `json:"enctoken"`
	LoginTime     string `json:"login_time"`
}

// Client represents the Kite API client.
type Client struct {
	debug      bool
	httpClient *http.Client
	baseURI    string
	logger     *log.Logger
}

// New creates a new Kite API client.
func New() *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: requestTimeout,
		},
		baseURI: defaultBaseURI,
		logger:  log.New(io.Discard, "[KiteSession] ", log.LstdFlags),
	}
}

// SetBaseURI sets a custom base URI for the API endpoints.
func (c *Client) SetBaseURI(uri string) {
	c.baseURI = uri
}

// SetDebug enables or disables debug mode for the client.
func (c *Client) SetDebug(debug bool) {
	c.debug = debug
	if debug {
		c.logger.SetOutput(io.Writer(os.Stdout))
	} else {
		c.logger.SetOutput(io.Discard)
	}
}

// SetTimeout sets the timeout for HTTP requests.
func (c *Client) SetTimeout(timeout time.Duration) {
	c.httpClient.Timeout = timeout
}

// GenerateSession generates a new Kite session using the provided credentials.
func (c *Client) GenerateSession(userID, password, totpValue string) (*Session, error) {
	loginResp, err := c.doLogin(userID, password)
	if err != nil {
		return nil, fmt.Errorf("login failed: %w", err)
	}

	// Check if two-factor authentication type is correct
	if loginResp.Data.TwofaType != "totp" {
		return nil, fmt.Errorf("incorrect twofa_type: %w", err)
	}

	return c.doTwofa(userID, totpValue, loginResp)
}

// doLogin performs the login step of the authentication process.
func (c *Client) doLogin(userID, password string) (*loginResponse, error) {
	data := url.Values{
		"user_id":  {userID},
		"password": {password},
	}

	req, err := c.newRequest(http.MethodPost, uriLogin, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating login request: %w", err)
	}

	var loginResp loginResponse
	if err := c.doRequest(req, &loginResp); err != nil {
		return nil, fmt.Errorf("executing login request: %w", err)
	}

	return &loginResp, nil
}

// doTwofa performs the two-factor authentication step of the authentication process.
func (c *Client) doTwofa(userID, totpValue string, loginResp *loginResponse) (*Session, error) {
	data := url.Values{
		"user_id":     {userID},
		"request_id":  {loginResp.Data.RequestID},
		"twofa_type":  {loginResp.Data.TwofaType},
		"twofa_value": {totpValue},
	}

	req, err := c.newRequest(http.MethodPost, uriTwofa, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating twofa request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing twofa request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("twofa request failed with status: %s", resp.Status)
	}

	session := &Session{
		Username:      loginResp.Data.Profile.UserName,
		UserShortname: loginResp.Data.Profile.UserShortname,
		LoginTime:     time.Now().Format("2006-01-02 15:04:05"),
	}

	for _, cookie := range resp.Cookies() {
		switch cookie.Name {
		case "user_id":
			session.UserID = cookie.Value
		case "public_token":
			session.PublicToken = cookie.Value
		case "kf_session":
			session.KFSession = cookie.Value
		case "enctoken":
			session.Enctoken = cookie.Value
		}
	}

	if session.Enctoken == "" {
		return nil, fmt.Errorf("enctoken not found in response cookies")
	}

	return session, nil
}

// CheckEnctokenValid checks if the provided enctoken is valid.
func (c *Client) CheckEnctokenValid(enctoken string) (bool, error) {
	req, err := c.newRequest(http.MethodGet, uriUserProfile, nil)
	if err != nil {
		return false, fmt.Errorf("creating profile request: %w", err)
	}

	req.Header.Set("Authorization", "enctoken "+enctoken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("executing profile request: %w", err)
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK, nil
}

// newRequest creates a new HTTP request with common headers.
func (c *Client) newRequest(method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, c.baseURI+path, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", accept)
	req.Header.Set("Content-Type", contentType)

	if c.debug {
		c.logger.Printf("Request URL: %s %s\n", method, req.URL.String())
		if body != nil {
			bodyBytes, _ := io.ReadAll(body)
			c.logger.Printf("Request Body: %s\n", string(bodyBytes))
			// Reset the body reader
			req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}
	}

	return req, nil
}

// doRequest performs an HTTP request and decodes the JSON response.
func (c *Client) doRequest(req *http.Request, v interface{}) error {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if c.debug {
		c.logger.Printf("Response Status: %s\n", resp.Status)
		bodyBytes, _ := io.ReadAll(resp.Body)
		c.logger.Printf("Response Body: %s\n", string(bodyBytes))
		// Reset the body reader
		resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	if resp.StatusCode != http.StatusOK {
		var errResp errorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			return fmt.Errorf("failed to decode error response: %w", err)
		}
		return fmt.Errorf("%s: %s", errResp.ErrorType, errResp.Message)
	}

	return json.NewDecoder(resp.Body).Decode(v)
}

// loginResponse represents the response from the login API.
type loginResponse struct {
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

// errorResponse represents the error response from the API.
type errorResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	ErrorType string `json:"error_type"`
}
