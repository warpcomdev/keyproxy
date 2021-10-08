package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

// MAX_TOKEN_SIZE is the maximum token size returned by auth
const MAX_TOKEN_SIZE = 65536

type Keystone struct {
	URL    string
	Client http.Client
}

// ErrorEmptyAuthResponse returned when response to auth request is empty
var ErrorEmptyAuthResponse = errors.New("Empty body in auth response")

// ErrorUnauthorized encapsulates the error returned by Keystone
type ErrorUnauthorized string

func (err ErrorUnauthorized) Error() string {
	return string(err)
}

func (k *Keystone) restLogin(logger *log.Entry, cred Credentials, pass string) (string, time.Time, error) {

	// Build auth request. Keystone is crazy.
	var body struct {
		Auth struct {
			Identity struct {
				Methods  []string `json:"methods"`
				Password struct {
					User struct {
						Domain struct {
							Name string `json:"name"`
						} `json:"domain"`
						Name     string `json:"name"`
						Password string `json:"password"`
					} `json:"user"`
				} `json:"password"`
			} `json:"identity"`
			Scope struct {
				Domain struct {
					Name string `json:"name"`
				} `json:"domain"`
			} `json:"scope"`
		} `json:"auth"`
	}
	body.Auth.Identity.Methods = []string{"password"}
	body.Auth.Identity.Password.User.Domain.Name = cred.Service
	body.Auth.Identity.Password.User.Name = cred.Username
	body.Auth.Identity.Password.User.Password = pass
	body.Auth.Scope.Domain.Name = cred.Service

	payload := &bytes.Buffer{}
	if err := json.NewEncoder(payload).Encode(body); err != nil {
		return "", time.Time{}, err
	}
	resp, err := k.Client.Post(k.URL, "application/json", payload)
	if err != nil {
		return "", time.Time{}, err
	}
	return k.decodeResponse(logger, resp, payload)
}

func (k *Keystone) decodeResponse(logger *log.Entry, resp *http.Response, payload *bytes.Buffer) (string, time.Time, error) {

	// Defer cleaning response body
	defer func() {
		if resp != nil && resp.Body != nil {
			io.Copy(ioutil.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
	payload.Reset()
	if resp == nil || resp.Body == nil {
		return "", time.Time{}, ErrorEmptyAuthResponse
	}

	// No error, just invalid credentials
	if resp.StatusCode != 201 {
		var jsonError struct {
			Error struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
				Title   string `json:"title"`
			} `json:"error"`
		}
		decoder := json.NewDecoder(io.LimitReader(resp.Body, MAX_TOKEN_SIZE))
		if err := decoder.Decode(&jsonError); err != nil {
			return "", time.Time{}, err
		}
		return "", time.Time{}, ErrorUnauthorized(jsonError.Error.Message)
	}

	token := resp.Header.Get("X-Subject-Token")
	if token == "" {
		return "", time.Time{}, nil
	}

	var responseBody struct {
		Token struct {
			Roles []struct {
				Name string `json:"name"`
			} `json:"roles"`
			Expires string `json:"expires_at"`
		} `json:"token"`
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, MAX_TOKEN_SIZE))
	if err := decoder.Decode(&responseBody); err != nil {
		return "", time.Time{}, err
	}

	expires, err := time.Parse(time.RFC3339, responseBody.Token.Expires)
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}

func (k *Keystone) restRefresh(logger *log.Entry, cred Credentials, token string) (string, time.Time, error) {
	var body struct {
		Auth struct {
			Identity struct {
				Methods []string `json:"methods"`
				Token   struct {
					Id string `json:"id"`
				} `json:"token"`
			} `json:"identity"`
		} `json:"auth"`
	}
	body.Auth.Identity.Methods = []string{"token"}
	body.Auth.Identity.Token.Id = token

	payload := &bytes.Buffer{}
	if err := json.NewEncoder(payload).Encode(body); err != nil {
		return "", time.Time{}, err
	}
	resp, err := k.Client.Post(k.URL, "application/json", payload)
	if err != nil {
		return "", time.Time{}, err
	}
	return k.decodeResponse(logger, resp, payload)
}
