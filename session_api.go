package kitesession

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// SessionTokenResponse is the response from the session token API
type SessionTokenResponse struct {
	Status string `json:"status"`
	Data   struct {
		UserType      string   `json:"user_type"`
		Email         string   `json:"email"`
		UserName      string   `json:"user_name"`
		UserShortname string   `json:"user_shortname"`
		Broker        string   `json:"broker"`
		Exchanges     []string `json:"exchanges"`
		Products      []string `json:"products"`
		OrderTypes    []string `json:"order_types"`
		AvatarURL     any      `json:"avatar_url"`
		UserID        string   `json:"user_id"`
		APIKey        string   `json:"api_key"`
		AccessToken   string   `json:"access_token"`
		PublicToken   string   `json:"public_token"`
		RefreshToken  string   `json:"refresh_token"`
		Enctoken      string   `json:"enctoken"`
		LoginTime     string   `json:"login_time"`
		Meta          struct {
			DematConsent string `json:"demat_consent"`
		} `json:"meta"`
	} `json:"data"`
}

// getSessID gets the sess_id from the login URL with context support.
// It initiates the API session flow and retrieves the session ID.
func (c *KiteSessionClient) getSessID(ctx context.Context) (string, string, error) {
	loginURL := fmt.Sprintf("%s?v=3&api_key=%s", ConnectLoginURL, c.APIKey)

	loginRequest, err := http.NewRequest(http.MethodGet, loginURL, nil)
	if err != nil {
		return "", "", err
	}

	// add context to request
	loginRequest = loginRequest.WithContext(ctx)

	resp, err := c.client.Do(loginRequest)
	if err != nil {
		return "", "", err
	}

	if resp.StatusCode != http.StatusFound {
		c.KiteSessionError = &KiteSessionError{
			ErrorCode: resp.StatusCode,
			ErrorType: "KiteException",
			Message:   "Failed to get `sess_id`",
		}
		return "", "", errors.New(c.KiteSessionError.Error())
	}

	location := resp.Header.Get("Location")

	locationURL, err := url.Parse(location)
	if err != nil {
		c.KiteSessionError = &KiteSessionError{
			ErrorCode: 500,
			ErrorType: "KiteException",
			Message:   "Failed to parse location URL: " + err.Error(),
		}
		return "", "", errors.New(c.KiteSessionError.Error())
	}

	query := locationURL.Query()
	sessID := query.Get("sess_id")
	if sessID == "" {
		c.KiteSessionError = &KiteSessionError{
			ErrorCode: 500,
			ErrorType: "KiteException",
			Message:   "Failed to get `sess_id` from location URL",
		}
		return "", "", errors.New(c.KiteSessionError.Error())
	}

	var kfSession string
	cookies := resp.Cookies()
	for _, cookie := range cookies {
		if cookie.Name == "kf_session" {

			kfSession = cookie.Value
			break
		}
	}
	return sessID, kfSession, nil

}

// getRequestToken gets the request token from the finish URL with context support.
// It completes the authentication flow and retrieves the request token.
func (c *KiteSessionClient) getRequestToken(ctx context.Context, sessID string) (string, error) {
	finishURL := fmt.Sprintf("%s?v=3&api_key=%s&sess_id=%s", ConnectFinishURL, c.APIKey, sessID)

	finishRequest, err := http.NewRequest(http.MethodGet, finishURL, nil)
	if err != nil {
		return "", err
	}

	// add context to request
	finishRequest = finishRequest.WithContext(ctx)

	resp, err := c.client.Do(finishRequest)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusFound {
		c.KiteSessionError = &KiteSessionError{
			ErrorCode: resp.StatusCode,
			ErrorType: "KiteException",
			Message:   "Failed to get request token",
		}
		return "", errors.New(c.KiteSessionError.Error())
	}

	location := resp.Header.Get("Location")
	locationURL, err := url.Parse(location)
	if err != nil {
		c.KiteSessionError = &KiteSessionError{
			ErrorCode: 500,
			ErrorType: "KiteException",
			Message:   "Failed to parse location URL: " + err.Error(),
		}
		return "", errors.New(c.KiteSessionError.Error())
	}

	query := locationURL.Query()
	requestToken := query.Get("request_token")
	if requestToken == "" {
		c.KiteSessionError = &KiteSessionError{
			ErrorCode: 500,
			ErrorType: "KiteException",
			Message:   "Failed to get `request_token` from location URL",
		}
		return "", errors.New(c.KiteSessionError.Error())
	}
	return requestToken, nil
}

// generateSessionToken generates the session token with context support.
// It exchanges the request token for an access token.
func (c *KiteSessionClient) generateSessionToken(ctx context.Context, requestToken string) (*SessionTokenResponse, error) {
	// generate checksum
	data := c.APIKey + requestToken + c.APISecret
	hash := sha256.Sum256([]byte(data))
	checksum := hex.EncodeToString(hash[:])

	// generate payload
	payload := url.Values{}
	payload.Set("api_key", c.APIKey)
	payload.Set("request_token", requestToken)
	payload.Set("checksum", checksum)

	tokenRequest, err := http.NewRequest(http.MethodPost, SessionTokenURL, strings.NewReader(payload.Encode()))
	if err != nil {
		return nil, err
	}

	// add context to request
	tokenRequest = tokenRequest.WithContext(ctx)

	for key, value := range defaultHeaders {
		tokenRequest.Header.Set(key, value)
	}

	resp, err := c.client.Do(tokenRequest)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &KiteSessionError{
			ErrorCode: resp.StatusCode,
			ErrorType: "KiteException",
			Message:   "Failed to generate session token",
		}
	}

	var sessionTokenResponse SessionTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&sessionTokenResponse); err != nil {
		return nil, fmt.Errorf("failed to decode session token response: %w", err)
	}

	return &sessionTokenResponse, nil

}
