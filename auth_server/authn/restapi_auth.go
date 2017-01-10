package authn

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang/glog"
)

const (
	keyAuthAPIEndpoint = "AUTH_API_ENDPOINT"
)

// RestAPIAuthConfig is inspired by MongoAuthConfig
type RestAPIAuthConfig struct {
	Method   string `yaml:"method"`
	Endpoint string `yaml:"endpoint"`
}

// RestAPIAuth is inspired by MongoAuth
type RestAPIAuth struct {
	config *RestAPIAuthConfig
}

// RestAPIUser is inspired by authUserEntry
type RestAPIUser struct {
	Email    *string `yaml:"email,omitempty" json:"email,omitempty"`
	Password *string `yaml:"password,omitempty" json:"password,omitempty"`
}

// RestAPIRespBody is the body of RestAPI response
type RestAPIRespBody struct {
	Code  int    `json:"code"`
	Msg   string `json:"msg"`
	Token string `json:"token"`
}

// NewRestAPIAuth creates a new RestAPIAuth
func NewRestAPIAuth(c *RestAPIAuthConfig) (*RestAPIAuth, error) {
	// Attempt to create config.
	if e := os.Getenv(keyAuthAPIEndpoint); e != "" {
		c.Endpoint = e
	}

	return &RestAPIAuth{
		config: c,
	}, nil
}

// Authenticate is inspired by MongoAuth.Authenticate()
func (rauth *RestAPIAuth) Authenticate(account string, password PasswordString) (bool, Labels, error) {
	for true {
		result, err := rauth.authenticate(account, password)
		if err == io.EOF {
			glog.Warningf("EOF error received from the RestAPI. Retrying connection")
			time.Sleep(time.Second)
			continue
		}
		return result, nil, err
	}

	return false, nil, errors.New("Unable to communicate with the RestAPI.")
}

func (rauth *RestAPIAuth) authenticate(account string, password PasswordString) (bool, error) {
	// Get Users from CouchDB
	glog.V(2).Infof("Checking user %s from remote restful server %s",
		account, rauth.config.Endpoint)

	u := fmt.Sprintf("http://%s/user/login?email=%s&password=%s",
		rauth.config.Endpoint, account, string(password))

	req, err := http.NewRequest(rauth.config.Method, u, nil)
	if err != nil {
		return false, err
	}

	// send request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}

	// decode resp
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	apiResp := &RestAPIRespBody{}
	err = json.Unmarshal(body, apiResp)
	if err != nil {
		return false, err
	}

	// judge
	if apiResp.Code == 200 && apiResp.Msg == "ok" {
		return true, nil
	}

	return false, NoMatch
}

// Validate ensures that any custom config options
// in a Config are set correctly.
func (c *RestAPIAuthConfig) Validate(configKey string) (err error) {
	// Now check additional config fields.
	if len(strings.TrimSpace(c.Endpoint)) == 0 {
		return fmt.Errorf("%s.endpoint is required", configKey)
	}
	if len(strings.TrimSpace(c.Method)) == 0 {
		return fmt.Errorf("%s.method is required", configKey)
	}
	return nil
}

func (rauth *RestAPIAuth) Stop() {

}

func (cauth *RestAPIAuth) Name() string {
	return "RestAPI"
}
