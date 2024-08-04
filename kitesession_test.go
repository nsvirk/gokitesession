package kitesession

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	client := New()
	assert.NotNil(t, client)
	assert.Equal(t, defaultBaseURI, client.baseURI)
	assert.Equal(t, requestTimeout, client.httpClient.Timeout)
}

func TestSetBaseURI(t *testing.T) {
	client := New()
	newURI := "https://test.example.com"
	client.SetBaseURI(newURI)
	assert.Equal(t, newURI, client.baseURI)
}

func TestSetDebug(t *testing.T) {
	client := New()
	client.SetDebug(true)
	assert.True(t, client.debug)
	client.SetDebug(false)
	assert.False(t, client.debug)
}

func TestSetTimeout(t *testing.T) {
	client := New()
	newTimeout := 10 * time.Second
	client.SetTimeout(newTimeout)
	assert.Equal(t, newTimeout, client.httpClient.Timeout)
}

func TestGenerateSession(t *testing.T) {
	// Mock server to simulate Kite API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case uriLogin:
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"success","data":{"request_id":"test_request_id","twofa_type":"totp"}}`))
		case uriTwofa:
			http.SetCookie(w, &http.Cookie{Name: "enctoken", Value: "test_enctoken"})
			http.SetCookie(w, &http.Cookie{Name: "user_id", Value: "test_user_id"})
			http.SetCookie(w, &http.Cookie{Name: "public_token", Value: "test_public_token"})
			http.SetCookie(w, &http.Cookie{Name: "kf_session", Value: "test_kf_session"})
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"success"}`))
		}
	}))
	defer server.Close()

	client := New()
	client.SetBaseURI(server.URL)

	session, err := client.GenerateSession("test_user", "test_password", "123456")
	require.NoError(t, err)
	assert.NotNil(t, session)
	assert.Equal(t, "test_enctoken", session.Enctoken)
	assert.Equal(t, "test_user_id", session.UserID)
	assert.Equal(t, "test_public_token", session.PublicToken)
	assert.Equal(t, "test_kf_session", session.KFSession)
}

func TestCheckEnctokenValid(t *testing.T) {
	// Mock server to simulate Kite API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "enctoken valid_token" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer server.Close()

	client := New()
	client.SetBaseURI(server.URL)

	valid, err := client.CheckEnctokenValid("valid_token")
	require.NoError(t, err)
	assert.True(t, valid)

	valid, err = client.CheckEnctokenValid("invalid_token")
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestDoLogin(t *testing.T) {
	// Mock server to simulate Kite API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success","data":{"request_id":"test_request_id","twofa_type":"totp"}}`))
	}))
	defer server.Close()

	client := New()
	client.SetBaseURI(server.URL)

	resp, err := client.doLogin("test_user", "test_password")
	require.NoError(t, err)
	assert.Equal(t, "test_request_id", resp.Data.RequestID)
	assert.Equal(t, "totp", resp.Data.TwofaType)
}

func TestDoTwofa(t *testing.T) {
	// Mock server to simulate Kite API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "enctoken", Value: "test_enctoken"})
		http.SetCookie(w, &http.Cookie{Name: "user_id", Value: "test_user_id"})
		http.SetCookie(w, &http.Cookie{Name: "public_token", Value: "test_public_token"})
		http.SetCookie(w, &http.Cookie{Name: "kf_session", Value: "test_kf_session"})
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success"}`))
	}))
	defer server.Close()

	client := New()
	client.SetBaseURI(server.URL)

	loginResp := &loginResponse{
		Data: struct {
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
		}{
			RequestID: "test_request_id",
			TwofaType: "totp",
			Profile: struct {
				UserName      string `json:"user_name"`
				UserShortname string `json:"user_shortname"`
				AvatarURL     any    `json:"avatar_url"`
			}{
				UserName:      "Test User",
				UserShortname: "testuser",
			},
		},
	}

	session, err := client.doTwofa("test_user", "123456", loginResp)
	require.NoError(t, err)
	assert.Equal(t, "test_enctoken", session.Enctoken)
	assert.Equal(t, "test_user_id", session.UserID)
	assert.Equal(t, "test_public_token", session.PublicToken)
	assert.Equal(t, "test_kf_session", session.KFSession)
	assert.Equal(t, "Test User", session.Username)
	assert.Equal(t, "testuser", session.UserShortname)
}

func TestGenerateTOTPValue(t *testing.T) {
	// Use a fixed TOTP secret for testing
	totpSecret := "JBSWY3DPEHPK3PXP"

	// Use a fixed UNIX timestamp for consistent test results
	fixedTimestamp := int64(1628069800) // August 4, 2021 12:10:00 UTC
	fixedTime := time.Unix(fixedTimestamp, 0)

	// Generate the expected TOTP value using the pquerna/otp library directly
	expectedTOTP, err := totp.GenerateCode(totpSecret, fixedTime)
	require.NoError(t, err, "Failed to generate expected TOTP value")

	// actual OTP for GenerateTOTPValue function
	actualTOTP := "055457"

	// Compare the results
	assert.Equal(t, expectedTOTP, actualTOTP, "Generated TOTP value doesn't match expected value")
}
