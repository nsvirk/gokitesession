package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockKiteSession is a mock of the KiteSession interface
type MockKiteSession struct {
	mock.Mock
}

func (m *MockKiteSession) GenerateSession(userID, password, totpValue string) (interface{}, error) {
	args := m.Called(userID, password, totpValue)
	return args.Get(0), args.Error(1)
}

func (m *MockKiteSession) CheckEnctokenValid(enctoken string) (bool, error) {
	args := m.Called(enctoken)
	return args.Bool(0), args.Error(1)
}

func TestGenerateTOTP(t *testing.T) {
	e := echo.New()

	tests := []struct {
		name           string
		requestBody    string
		expectedStatus int
		expectedError  bool
	}{
		{
			name:           "Valid TOTP Secret",
			requestBody:    `{"totp_secret": "JBSWY3DPEHPK3PXP"}`,
			expectedStatus: http.StatusOK,
			expectedError:  false,
		},
		{
			name:           "Empty TOTP Secret",
			requestBody:    `{"totp_secret": ""}`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  true,
		},
		{
			name:           "Invalid JSON",
			requestBody:    `{"totp_secret": }`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/session/totp", strings.NewReader(tt.requestBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			err := generateTOTP(c)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tt.expectedStatus, rec.Code)

			if !tt.expectedError {
				var response Response
				err := json.Unmarshal(rec.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "ok", response.Status)
				assert.NotNil(t, response.Data)
				data, ok := response.Data.(map[string]interface{})
				assert.True(t, ok)
				assert.NotEmpty(t, data["totp_value"])
			}
		})
	}
}

func TestGenerateSession(t *testing.T) {
	e := echo.New()
	mockKS := new(MockKiteSession)

	tests := []struct {
		name           string
		requestBody    string
		expectedStatus int
		expectedError  bool
		mockReturn     interface{}
		mockError      error
	}{
		{
			name:           "Valid Login Request",
			requestBody:    `{"user_id": "testuser", "password": "testpass", "totp_value": "123456"}`,
			expectedStatus: http.StatusOK,
			expectedError:  false,
			mockReturn:     map[string]string{"session_token": "test_token"},
			mockError:      nil,
		},
		{
			name:           "Missing Fields",
			requestBody:    `{"user_id": "testuser", "password": "testpass"}`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  true,
		},
		{
			name:           "Invalid JSON",
			requestBody:    `{"user_id": "testuser", "password": }`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/session/login", strings.NewReader(tt.requestBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			if !tt.expectedError {
				mockKS.On("GenerateSession", "testuser", "testpass", "123456").Return(tt.mockReturn, tt.mockError)
			}

			err := generateSession(c)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tt.expectedStatus, rec.Code)

			if !tt.expectedError {
				var response Response
				err := json.Unmarshal(rec.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "ok", response.Status)
				assert.NotNil(t, response.Data)
			}

			mockKS.AssertExpectations(t)
		})
	}
}

func TestCheckEnctoken(t *testing.T) {
	e := echo.New()
	mockKS := new(MockKiteSession)

	tests := []struct {
		name           string
		requestBody    string
		expectedStatus int
		expectedError  bool
		mockReturn     bool
		mockError      error
	}{
		{
			name:           "Valid Enctoken",
			requestBody:    `{"enctoken": "valid_enctoken"}`,
			expectedStatus: http.StatusOK,
			expectedError:  false,
			mockReturn:     true,
			mockError:      nil,
		},
		{
			name:           "Empty Enctoken",
			requestBody:    `{"enctoken": ""}`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  true,
		},
		{
			name:           "Invalid JSON",
			requestBody:    `{"enctoken": }`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/session/valid", strings.NewReader(tt.requestBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			if !tt.expectedError {
				mockKS.On("CheckEnctokenValid", "valid_enctoken").Return(tt.mockReturn, tt.mockError)
			}

			err := checkEnctoken(c)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tt.expectedStatus, rec.Code)

			if !tt.expectedError {
				var response Response
				err := json.Unmarshal(rec.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "ok", response.Status)
				assert.NotNil(t, response.Data)
				data, ok := response.Data.(map[string]interface{})
				assert.True(t, ok)
				assert.NotNil(t, data["is_valid"])
			}

			mockKS.AssertExpectations(t)
		})
	}
}
