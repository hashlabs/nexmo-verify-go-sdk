package nexmoVerifySDK

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

func helperMockResponse(t *testing.T, filePath, url string, success bool) {
	httpmock.Activate()
	response, err := ioutil.ReadFile(filePath)
	assert.Nil(t, err)

	var jsonResponse map[string]interface{}
	var responseBody map[string]interface{}
	key := "error"
	err = json.Unmarshal(response, &jsonResponse)
	assert.Nil(t, err)

	if success {
		key = "success"
	}

	jsonResponse = jsonResponse[key].(map[string]interface{})
	responseBody = jsonResponse["body"].(map[string]interface{})
	responseHeaders := jsonResponse["header"].(map[string]interface{})
	responseSignature := responseHeaders["X-NEXMO-RESPONSE-SIGNATURE"].(string)

	httpmock.RegisterResponder("GET", url,
		func(req *http.Request) (*http.Response, error) {
			encoded, err := json.MarshalIndent(responseBody, "", "    ")
			if err != nil {
				return nil, err
			}
			resp := httpmock.NewBytesResponse(200, encoded)
			resp.Header.Set("Content-Type", "application/json")
			resp.Header.Add("X-NEXMO-RESPONSE-SIGNATURE", responseSignature)

			return resp, nil
		},
	)
}
