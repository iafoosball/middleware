package sdk

import (
	"errors"
	"github.com/iafoosball/auth-service/jwt"
	"net/http"
	"strconv"
)

// JWTValidator constructor configures the connection with auth-service in order to validate incoming tokens in
// HTTP request headers. All fields are required
type JWTValidator struct {
	Protocol string
	Hostname string
	Port     int
}

// ValidateAuth against remote auth-service.
func (v JWTValidator) ValidateAuth(authStr string) (bool, error) {
	url := v.Protocol + "://" + v.Hostname + ":" + strconv.Itoa(v.Port) + jwt.ValidateTokenPath

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return false, err
	}
	req.Close = true
	req.Header.Set("Authorization", authStr)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	code := resp.StatusCode
	if code == 200 {
		return true, nil
	} else {
		return false, errors.New("Http Status Code Error: " + string(code))
	}
}
