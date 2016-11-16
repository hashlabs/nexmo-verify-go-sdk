# Nexmo Go Verify SDK

You use Nexmo Verify to verify that a user has access to a specific phone number. Nexmo sends a PIN code in an SMS or Text-To-Speech, your user enters this PIN into your App, you validate the PIN with Nexmo. With Verify SDK for Go you easily integrate Verify functionality into your App.

This implementation mimics the [Nexmo Android SDK](https://github.com/Nexmo/verify-android-sdk), since Golang is not a supported language.

## Usage

```go
import nexmo "github.com/hashlabs/nexmo-verify-go-sdk"

client := nexmo.NewClient(<appId>, <sharedSecret>)

response, err := client.VerifySearch(map[string]string {
  "device_id":         deviceId,
  "source_ip_address": "127.0.0.1",
  "number": "+521111111111",
})
if err != nil {
  panic(err)
}

// Use the response struct to check for the user_status
```

## Endpoints

* [x] GetToken
* [ ] Verify
* [ ] VerifyCheck
* [ ] VerifyControl
* [x] VerifySearch
* [ ] VerifyLogout

## License

MIT
