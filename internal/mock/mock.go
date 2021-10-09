package mock

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/warpcomdev/keyproxy/internal/auth"
	"github.com/warpcomdev/keyproxy/internal/kube"
	"github.com/warpcomdev/keyproxy/internal/server"
)

// AuthManager mocks the methods expected from auth
type AuthManager struct {
	Token    string
	Username string
	Password string
	Service  string
}

// Check implements server.AuthManager
func (a *AuthManager) Check(token string) (auth.Credentials, server.AuthSession, error) {
	if token != a.Token {
		return auth.Credentials{}, nil, errors.New("Invalid credentials")
	}
	return auth.Credentials{Service: a.Service, Username: a.Username}, a, nil
}

// Login implements server.AuthManager
func (a *AuthManager) Login(creds auth.Credentials, password string) (server.AuthSession, error) {
	if creds.Username != a.Username || creds.Service != a.Service || password != a.Password {
		return nil, errors.New("Invalid login credentials")
	}
	return a, nil
}

// Logout implements server.AuthSession
func (a *AuthManager) Logout() {
}

// JWT implements server.AuthSession
func (a *AuthManager) JWT() (string, time.Time, error) {
	return a.Token, time.Now().Add(time.Hour), nil
}

// KubeFactory mocks the methods expected from kube
type KubeFactory struct {
	kube.PodInfo
	cancel chan struct{}
}

// Delete implements server.KubeManager
func (k *KubeFactory) Delete(context.Context) error {
	if k.PodInfo.Type != "DELETED" {
		if k.cancel != nil {
			close(k.cancel)
			k.cancel = nil
		}
		cancel := make(chan struct{})
		k.cancel = cancel
		go func() {
			select {
			case <-cancel:
				return
			case <-time.After(20 * time.Second):
				k.PodInfo.Ready = false
			}
			select {
			case <-cancel:
				return
			case <-time.After(20 * time.Second):
				k.PodInfo.Type = "DELETED"
				k.PodInfo.Phase = "Unknown"
			}
		}()
	}
	return nil
}

// Proxy implements server.KubeManager
func (k *KubeFactory) Proxy(ctx context.Context, create bool) (*kube.PodProxy, kube.PodInfo, error) {
	if create {
		if k.PodInfo.Type != "DELETED" {
			return nil, k.PodInfo, errors.New("Pod already started")
		}
		if k.cancel != nil {
			close(k.cancel)
			k.cancel = nil
		}
		k.PodInfo.Type = "UPDATED"
		k.PodInfo.Phase = "Pending"
		cancel := make(chan struct{})
		k.cancel = cancel
		go func() {
			select {
			case <-cancel:
				return
			case <-time.After(20 * time.Second):
				k.PodInfo.Phase = "Running"
			}
			select {
			case <-cancel:
				return
			case <-time.After(20 * time.Second):
				k.PodInfo.Address = "1.2.3.4"
			}
			select {
			case <-cancel:
				return
			case <-time.After(20 * time.Second):
				k.PodInfo.Ready = true
			}
		}()
	}
	return nil, k.PodInfo, nil
}

// Find implements server.KubeFactory
func (k *KubeFactory) Find(auth.Credentials) (server.KubeManager, error) {
	return k, nil
}

type version string

// String implements fmt.Stringer
func (v version) String() string {
	return string(v)
}

// ServerVersion implements server.KubeFactory
func (k *KubeFactory) ServerVersion() (fmt.Stringer, error) {
	return version("Mock version"), nil
}
