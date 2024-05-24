package session

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// Session represents the Kite session data.
type Session struct {
	// user provided values
	UserId string `json:"user_id"`

	// from loginResponse body
	Username      string `json:"user_name"`
	UserShortname string `json:"user_shortname"`
	AvatarURL     string `json:"avatar_url"`

	// from twofaResponse cookies
	PublicToken string `json:"public_token"`
	KfSession   string `json:"kf_session"`
	Enctoken    string `json:"enctoken"`

	// generated value
	LoginTime string `json:"login_time"`
}

// loginResponse represents the login response data.
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

// errorResponse represents the error response data.
type errorResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	Data      any    `json:"data"`
	ErrorType string `json:"error_type"`
}

// Client represents interface for Kite Connect client.
type Client struct {
	userId     string
	enctoken   string
	debug      bool
	httpClient *http.Client
}

const (
	// defaultTimeout is the default timeout for the HTTP client.
	requestTimeout time.Duration = 7000 * time.Millisecond

	// request header values
	userAgent   = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
	contentType = "application/x-www-form-urlencoded"
	accept      = "application/json"

	// API endpoints
	kiteBaseURI    string = "https://kite.zerodha.com"
	URILogin       string = "/api/login"
	URITwofa       string = "/api/twofa"
	URIUserProfile string = "/oms/user/profile"
)

// New creates a new client.
func New(userId string) *Client {
	client := &Client{
		userId: userId,
		httpClient: &http.Client{
			Timeout: requestTimeout,
		},
	}
	return client
}

// SetDebug sets debug mode to enable HTTP logs.
func (c *Client) SetDebug(debug bool) {
	c.debug = debug
}

// SetTimeout sets request timeout for default http client.
func (c *Client) SetTimeout(timeout time.Duration) {
	c.httpClient.Timeout = timeout
}

// SetEnctoken sets the enctoken to the instance.
func (c *Client) SetEnctoken(eToken string) {
	c.enctoken = eToken
}

// GenerateTotpValue generates a totp value using the totpSecret
func (c *Client) GenerateTotpValue(totpSecret string) (string, error) {

	twofaValue, err := totp.GenerateCodeCustom(totpSecret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		if c.debug {
			log.Printf("Error generating totp value: %v", err)
		}
		return twofaValue, err
	}
	return twofaValue, nil

}

// GenerateSession generates a session using the password and totpValue
func (c *Client) GenerateSession(password, totpValue string) (*Session, error) {
	// return value
	var session *Session

	// doLogin and get the requestId
	loginResponse, err := c.doLogin(password)
	if err != nil {
		if c.debug {
			log.Printf("Error doing login: %v", err)
		}
		return session, err
	}

	// doTwofa and get the session data
	session, err = c.doTwofa(totpValue, loginResponse)
	if err != nil {
		if c.debug {
			log.Printf("Error doing twofa: %v", err)
		}
		return session, err
	}

	return session, nil

}

// doLogin makes a login request to the Kite API.
func (c *Client) doLogin(password string) (*loginResponse, error) {

	// login payload
	data := url.Values{}
	data.Set("user_id", c.userId)
	data.Set("password", password)
	payload := strings.NewReader(data.Encode())

	// create the login request
	loginURL := kiteBaseURI + URILogin
	r, err := http.NewRequest("POST", loginURL, payload)
	if err != nil {
		if c.debug {
			log.Printf("Error creating login request: %v", err)
		}
		return nil, err
	}

	// set the headers
	r.Header.Add("User-Agent", userAgent)
	r.Header.Add("Content-Type", contentType)
	r.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
	r.Header.Add("Accept", accept)

	// make the request and handle the response
	resp, err := c.httpClient.Do(r)
	if err != nil {
		if c.debug {
			log.Printf("Error making login request: %v", err)
		}
		return nil, err
	}

	// close the response body
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if c.debug {
			log.Printf("Error reading login response body: %v", err)
		}
		return nil, err
	}

	// -----------------------------------------------
	// Check for error on the basis of status_code
	// -----------------------------------------------
	if resp.StatusCode != http.StatusOK {

		// Create a new errorResponse
		var errorResp errorResponse

		// Unmarshal the JSON response into the errorResp
		err = json.Unmarshal(body, &errorResp)
		if err != nil {
			if c.debug {
				log.Printf("Error unmarshalling login error response: %v", err)
			}
			return nil, err
		}

		// return the error response
		err = errors.New(errorResp.Message)
		return nil, err

	}

	// -----------------------------------------------
	// Process the login response
	// -----------------------------------------------

	// Create a new LoginResponse
	var loginResp loginResponse

	// Unmarshal the JSON response into the loginResp
	err = json.Unmarshal(body, &loginResp)
	if err != nil {
		if c.debug {
			log.Printf("Error unmarshalling login response: %v", err)
		}
		return nil, err
	}

	return &loginResp, nil
}

// doTwofa makes a twofa request to the Kite API.
func (c *Client) doTwofa(totpValue string, loginResponse *loginResponse) (*Session, error) {

	// get the loginResponse requestId and twofaType
	requestId := loginResponse.Data.RequestID
	twofaType := loginResponse.Data.TwofaType

	// twofa payload
	data := url.Values{}
	data.Set("user_id", c.userId)
	data.Set("request_id", requestId)
	data.Set("twofa_type", twofaType)
	data.Set("twofa_value", totpValue)
	payload := strings.NewReader(data.Encode())

	// create the twofa request
	twofaURL := kiteBaseURI + URITwofa
	r, err := http.NewRequest("POST", twofaURL, payload) // URL-encoded payload
	if err != nil {
		if c.debug {
			log.Printf("Error creating twofa request: %v", err)
		}

		return nil, err
	}

	// set the headers
	r.Header.Add("User-Agent", userAgent)
	r.Header.Add("Content-Type", contentType)
	r.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
	r.Header.Add("Accept", accept)

	// make the request and handle the response
	resp, err := c.httpClient.Do(r)
	if err != nil {
		if c.debug {
			log.Printf("Error making twofa request: %v", err)
		}

		return nil, err
	}

	// close the response body
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if c.debug {
			log.Printf("Error reading twofa response body: %v", err)
		}
		return nil, err
	}

	// -----------------------------------------------
	// Check for error on the basis of status_code
	// -----------------------------------------------
	if resp.StatusCode != http.StatusOK {

		// Create a new errorResponse
		var errorResp errorResponse

		// Unmarshal the JSON response into the errorResp
		err = json.Unmarshal(body, &errorResp)
		if err != nil {
			if c.debug {
				log.Printf("Error unmarshalling twofa error response: %v", err)
			}
			return nil, err
		}

		// return the error response
		err = errors.New(errorResp.Message)
		return nil, err

	}

	// -----------------------------------------------
	// Process the twofa response
	// -----------------------------------------------
	var session Session

	// Get the response cookies
	cookies := resp.Cookies()

	// get data from the cookies to session
	for _, cookie := range cookies {
		if cookie.Name == "user_id" {
			session.UserId = cookie.Value
		}

		if cookie.Name == "public_token" {
			session.PublicToken = cookie.Value
		}

		if cookie.Name == "kf_session" {
			session.KfSession = cookie.Value
		}

		if cookie.Name == "enctoken" {
			session.Enctoken = cookie.Value
		}
	}

	// if session.userId is not empty, set session data
	if session.UserId != "" {
		session.Username = loginResponse.Data.Profile.UserName
		session.UserShortname = loginResponse.Data.Profile.UserShortname
		session.LoginTime = time.Now().Format("2006-01-02 15:04:05")
	}

	return &session, nil

}

// CheckEnctokenValid checks if the enctoken is valid or not.
func (c *Client) CheckEnctokenValid(enctoken string) (bool, error) {

	// Set the enctoken to the instance
	c.SetEnctoken(enctoken)

	// create the profile request
	profileURL := kiteBaseURI + URIUserProfile
	r, err := http.NewRequest("GET", profileURL, nil)
	if err != nil {
		if c.debug {
			log.Printf("Error creating profile request: %v", err)
		}
		return false, err
	}

	// set headers
	r.Header.Add("User-Agent", userAgent)
	r.Header.Add("Accept", accept)
	r.Header.Add("Authorization", "enctoken "+enctoken)

	// make th profile request and handle the response
	resp, err := c.httpClient.Do(r)
	if err != nil {
		if c.debug {
			log.Printf("Error making profile request: %v", err)
		}
		return false, err
	}

	// return the result based on http status code
	tokenValid := resp.StatusCode == http.StatusOK
	return tokenValid, nil

}
