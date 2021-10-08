package kube

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/warpcomdev/keyproxy/internal/clock"
)

// Manager handles the suscription to a pod's events
type Manager struct {
	// Timestamp of last update to be used by PodFactory.
	// Must be at the top of the struct for atomic ops to work.
	Timestamp  clock.AtomicTimestamp
	Logger     *log.Logger
	Descriptor *PodDescriptor
	// Scheme and port of the backend server to proxy to.
	// The IP address will be learnt from the kube cluster.
	Scheme         string
	Port           int
	ForwardedProto string
	Pool           httputil.BufferPool
	// latest status detected and resulting reverse proxy
	SessionCookie string
	latest        PodInfo
	proxy         *PodProxy
	// PendingDelete is set to true when pod is being destroyed
	pendingDelete bool
	// Mutex that protects everything
	mutex sync.Mutex
}

// Proxy returns a PodProxy instance to current pod's IP.
// If create == true, the pod will be scheduled for creation if not existing.
// Beware that the proxy might be nil if no IP, even when error == nil.
func (m *Manager) Proxy(ctx context.Context, api *API, create bool) (*PodProxy, PodInfo, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if err := m.updateStatus(ctx, api, create); err != nil {
		return nil, PodInfo{}, err
	}
	return m.proxy, m.latest, nil
}

// Delete the pod
func (m *Manager) Delete(ctx context.Context, api *API) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m.pendingDelete != false {
		return nil
	}
	m.pendingDelete = true
	err := api.DeletePod(ctx, m.Descriptor.Name)
	if err != nil {
		m.pendingDelete = false
		return err
	}
	return nil
}

// updateStatus must be called with the lock held
func (m *Manager) updateStatus(ctx context.Context, api *API, create bool) error {
	// If we don't know the pod status, ask for it
	if m.latest.Phase == "" {
		info, err := api.PodStatus(m.Descriptor.Name)
		if err != nil {
			return err
		}
		m.latest = info
		// In case the pod is running, build a reverse proxy
		if info.Type != Deleted && info.Phase == PodRunning && info.Address != "" {
			m.proxy = m.reverseProxy(info.Address)
		}
	}
	if m.latest.Type == Deleted && create {
		err := api.CreatePod(ctx, m.Descriptor)
		if err != nil {
			return err
		}
		// Change event so that we won't create it again
		m.latest.Type = Modified
	}
	return nil
}

// Update the pod info where there is a status change
func (m *Manager) Update(info PodInfo) error {
	logger := m.Logger.WithField("event", info)
	m.mutex.Lock()
	defer m.mutex.Unlock()
	switch {
	case info.Type == Deleted || info.Phase != PodRunning || info.Address == "":
		logger.Info("Pod not ready for proxy")
		m.proxy = nil
	case m.latest.Address != info.Address:
		logger.Info("Updating proxy address")
		m.proxy = m.reverseProxy(info.Address)
	}
	m.latest = info
	if info.Type == Deleted {
		m.pendingDelete = false
	}
	return nil
}

// JWTSession returns a JWT token and expiration time
type JWTSession interface {
	JWT() (string, time.Time, error)
}

type PodProxy struct {
	*httputil.ReverseProxy
	sessionCookie string
	jwtMutex      sync.Mutex
	jwtSession    JWTSession
}

// CurrentSession resets the auth Session
func (p *PodProxy) CurrentSession(session JWTSession) {
	p.jwtMutex.Lock()
	p.jwtSession = session
	p.jwtMutex.Unlock()
}

func (pp *PodProxy) modifyResponse(response *http.Response) error {
	pp.jwtMutex.Lock()
	session := pp.jwtSession
	pp.jwtMutex.Unlock()
	token, exp, err := session.JWT()
	if err != nil && token != "" {
		cookie := http.Cookie{
			Name:     pp.sessionCookie,
			Value:    token,
			Expires:  exp,
			Path:     "/",
			HttpOnly: true,
		}
		response.Header.Add("Set-Cookie", cookie.String())
	}
	// Replace insecure ws:// calls in code with wss://
	// culprits:
	// - /editor/js/app-main.js
	// - /editor/js/service-console-list-manager.js
	// This won't work - the files are delivered in gzip encoding
	/*
		rh := response.Header.Get("Content-Type")
		if m.ForwardedProto == "https" && strings.EqualFold(rh, "application/javascript") {
			logger := m.Logger.WithFields(log.Fields{"url": response.Request.URL.String()})
			logger.Debug("Triggering body text replacement")
			response.Body = &ReplaceReader{
				Logger: logger,
				body:   response.Body,
			}
			// Make sure it's both a readCloser and a flusher
			_ = response.Body.(io.ReadCloser)
			_ = response.Body.(http.Flusher)
		}
	*/
	return nil
}

// reverseProxy builds the reverse proxy instance.
func (m *Manager) reverseProxy(address string) *PodProxy {
	target := &url.URL{
		Scheme: m.Scheme,
		Host:   fmt.Sprintf("%s:%d", address, m.Port),
	}
	pp := &PodProxy{
		ReverseProxy:  httputil.NewSingleHostReverseProxy(target),
		sessionCookie: m.SessionCookie,
	}
	// Refresh cookie in proxy response
	pp.ModifyResponse = pp.modifyResponse
	pp.BufferPool = m.Pool
	if m.ForwardedProto != "" {
		director := pp.Director
		pp.Director = func(r *http.Request) {
			director(r)
			r.Header.Set("X-Forwarded-Proto", m.ForwardedProto)
		}
	}
	return pp
}
