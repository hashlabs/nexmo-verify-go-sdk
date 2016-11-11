package nexmoVerifySDK

import (
	"crypto/md5"
	"encoding/hex"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

func TestCreateSignature(t *testing.T) {
	// Context: With a map[string]string
	sharedSecret := "secret"
	params := map[string]string{
		"device_id": "my-token",
		"app_id":    "myappid",
	}
	signature := md5.Sum([]byte(`&app_id=myappid&device_id=my-tokensecret`))
	expectedHash := hex.EncodeToString(signature[:])

	// Context: When calling createSignature
	hash := createSignature(params, sharedSecret)

	// Context: It returns a the expected hash value
	assert.Equal(t, expectedHash, hash)
}

func TestGenerateParameters(t *testing.T) {
	// Context: With a map[string]string
	sharedSecret := "secret"
	appId := "appId"
	params := map[string]string{
		"device_id": "my-token",
		"app_id":    "myappid",
	}

	// Context: When calling generateParameters
	newParams := generateParameters(params, appId, sharedSecret)

	// Context: It returns a new map with app_id, timestamp and sig
	assert.NotEqual(t, params, newParams)
	assert.Equal(t, appId, newParams["app_id"])
	assert.NotNil(t, newParams["sig"])
	assert.NotNil(t, newParams["timestamp"])
}

func TestGetToken(t *testing.T) {
	// Context: With all the required parameters
	helperMockResponse(t, "./test_fixtures/get_token_response.json", "https://api.nexmo.com/sdk/token/json", true)
	defer httpmock.DeactivateAndReset()

	appId := "aa6215a6-2c00-4625-85e9-6426bb377027"
	sharedSecret := "f3ac8cc9b1ddde5"
	deviceId := "fq_7le_qTzY:APA91bEm38BfOBh4hDEWHyKe0FdNJPpyJ86hX9VX_0Zq6clsrhPm0ZKkI2ZlxTw4DToTFF768rS-"
	nexmo := NewClient(appId, sharedSecret)

	// Context: When calling GetToken(parameters)
	response, err := nexmo.GetToken(map[string]string{
		"device_id":         deviceId,
		"source_ip_address": "127.0.0.1",
	})

	// Context: Returns a success response
	assert.Nil(t, err)
	assert.Equal(t, 0, response.ResultCode)
	assert.Equal(t, "OK", response.ResultMessage)
}

func TestGetTokenError(t *testing.T) {
	// Context: With source_ip_address param missing
	helperMockResponse(t, "./test_fixtures/get_token_response.json", "https://api.nexmo.com/sdk/token/json", false)
	defer httpmock.DeactivateAndReset()

	appId := "aa6215a6-2c00-4625-85e9-6426bb377027"
	sharedSecret := "f3ac8cc9b1ddde5"
	deviceId := "fq_7le_qTzY:APA91bEm38BfOBh4hDEWHyKe0FdNJPpyJ86hX9VX_0Zq6clsrhPm0ZKkI2ZlxTw4DToTFF768rS-"
	nexmo := NewClient(appId, sharedSecret)

	// Context: When calling GetToken(parameters)
	response, err := nexmo.GetToken(map[string]string{
		"device_id": deviceId,
	})

	// Context: Returns an error response
	assert.Nil(t, err)
	assert.Equal(t, 51, response.ResultCode)
}

func TestVerifySearch(t *testing.T) {
	// Context: With all the required parameters
	helperMockResponse(t, "./test_fixtures/get_token_response.json", "https://api.nexmo.com/sdk/token/json", true)
	helperMockResponse(t, "./test_fixtures/search_user_status_response.json", "https://api.nexmo.com/sdk/verify/search/json", true)
	defer httpmock.DeactivateAndReset()

	appId := "aa6215a6-2c00-4625-85e9-6426bb377027"
	sharedSecret := "f3ac8cc9b1ddde5"
	deviceId := "fq_7le_qTzY:APA91bEm38BfOBh4hDEWHyKe0FdNJPpyJ86hX9VX_0Zq6clsrhPm0ZKkI2ZlxTw4DToTFF768rS-"
	nexmo := NewClient(appId, sharedSecret)

	// Context: When calling GetToken(parameters)
	response, err := nexmo.VerifySearch(map[string]string{
		"device_id":         deviceId,
		"source_ip_address": "127.0.0.1",
		"number":            "+521111111111",
	})

	// Context: Returns a success response
	assert.Nil(t, err)
	assert.Equal(t, 0, response.ResultCode)
	assert.Equal(t, "OK", response.ResultMessage)
	assert.Equal(t, "unknown", response.UserStatus)
}

func TestVerifySearchError(t *testing.T) {
	// Context: With all the required parameters
	helperMockResponse(t, "./test_fixtures/get_token_response.json", "https://api.nexmo.com/sdk/token/json", true)
	helperMockResponse(t, "./test_fixtures/search_user_status_response.json", "https://api.nexmo.com/sdk/verify/search/json", false)
	defer httpmock.DeactivateAndReset()

	appId := "aa6215a6-2c00-4625-85e9-6426bb377027"
	sharedSecret := "f3ac8cc9b1ddde5"
	deviceId := "fq_7le_qTzY:APA91bEm38BfOBh4hDEWHyKe0FdNJPpyJ86hX9VX_0Zq6clsrhPm0ZKkI2ZlxTw4DToTFF768rS-"
	nexmo := NewClient(appId, sharedSecret)

	// Context: When calling GetToken(parameters)
	response, err := nexmo.VerifySearch(map[string]string{
		"device_id":         deviceId,
		"source_ip_address": "127.0.0.1",
	})

	// Context: Returns a success response
	assert.Nil(t, err)
	assert.Equal(t, 53, response.ResultCode)
}

func TestVerifySearchTokenError(t *testing.T) {
	// Context: With all the required parameters
	helperMockResponse(t, "./test_fixtures/get_token_response.json", "https://api.nexmo.com/sdk/token/json", false)
	helperMockResponse(t, "./test_fixtures/search_user_status_response.json", "https://api.nexmo.com/sdk/verify/search/json", false)
	defer httpmock.DeactivateAndReset()

	appId := "aa6215a6-2c00-4625-85e9-6426bb377027"
	sharedSecret := "f3ac8cc9b1ddde5"
	deviceId := "fq_7le_qTzY:APA91bEm38BfOBh4hDEWHyKe0FdNJPpyJ86hX9VX_0Zq6clsrhPm0ZKkI2ZlxTw4DToTFF768rS-"
	nexmo := NewClient(appId, sharedSecret)

	// Context: When calling GetToken(parameters)
	_, err := nexmo.VerifySearch(map[string]string{
		"device_id":         deviceId,
		"source_ip_address": "127.0.0.1",
	})

	// Context: Returns a success response
	assert.NotNil(t, err)
}
