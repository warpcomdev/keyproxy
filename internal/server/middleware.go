package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/gorilla/csrf"
	log "github.com/sirupsen/logrus"
)

type middleware struct {
	http.Handler
}

// IsAPICall returns true if request Accepts 'application/json'
func isApiCall(r *http.Request) bool {
	for _, accept := range r.Header.Values("Accept") {
		if strings.HasPrefix(accept, "application/json") {
			return true
		}
	}
	return false
}

// apiReply serializes an API reply
func apiReply(logger *log.Entry, w http.ResponseWriter, data interface{}) {
	encoder := json.NewEncoder(w)
	w.Header().Add(http.CanonicalHeaderKey("Content-Type"), "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := encoder.Encode(data); err != nil {
		logger.WithError(err).Error("Failed to serialize API response")
	}
}

// Middleware constructor facilitates chaining middlewares
func Middleware(handlerFunc func(w http.ResponseWriter, r *http.Request)) *middleware {
	return &middleware{
		Handler: http.HandlerFunc(handlerFunc),
	}
}

// CSRF uses gorilla.csrf to CSRF protect paths
func (m *middleware) CSRF(csrfSecret []byte, options ...csrf.Option) *middleware {
	handler := m.Handler
	setHeader := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(CSRFHEADER, csrf.Token(r))
		handler.ServeHTTP(w, r)
	}
	m.Handler = csrf.Protect(csrfSecret, options...)(http.HandlerFunc(setHeader))
	return m
}

// CSP adds Content-Security-Policy
func (m *middleware) CSP(sandbox, upgradeInsecure bool) *middleware {
	handler := m.Handler
	m.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		csp := "frame-ancestors 'none'"
		if sandbox {
			csp = csp + "; default-src 'self'"
		}
		if upgradeInsecure {
			csp = csp + "; upgrade-insecure-requests"
		}
		w.Header().Set("Content-Security-Policy", csp)
		handler.ServeHTTP(w, r)
	})
	return m
}

// FakeCSRF sets a fake CSRFHeader when proxyprotocol is http.
func (m *middleware) FakeCSRF() *middleware {
	handler := m.Handler
	m.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(CSRFHEADER, "CSRF-Disabled-over-HTTP")
		handler.ServeHTTP(w, r)
	})
	return m
}

// Auth checks authentication and stores session in context.
func (m *middleware) Auth(scheme string, cookieName string, check func(ctx context.Context, token string) (context.Context, error), loginPath string, redirectAlways bool) *middleware {
	handler := m.Handler
	m.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Use different redirect code depending on the method
		statusRedirect := http.StatusTemporaryRedirect
		if r.Method != http.MethodGet {
			statusRedirect = http.StatusSeeOther
		}

		// Check if cookie exists
		authCookie, err := r.Cookie(cookieName)
		var ctx context.Context
		if err != nil && !errors.Is(err, http.ErrNoCookie) {
			log.WithError(err).Error("Failed to get auth cookie")
		}
		if err == nil && authCookie != nil {
			// Check cookie credentials
			ctx, err = check(r.Context(), authCookie.Value)
			if err != nil {
				log.WithError(err).Error("Failed to check credentials")
				ctx = nil // fallthrough to the next "if"
			}
		}

		// Check if we could retrieve the context
		if ctx == nil {
			if !isApiCall(r) && (redirectAlways || (r.URL.Path == "/" && r.Method == http.MethodGet)) {
				redirectPath := fmt.Sprintf("%s://%s%s", scheme, r.Host, loginPath)
				http.Redirect(w, r, redirectPath, statusRedirect)
			} else {
				http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			}
			return
		}
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
	return m
}

// Exhaust the request body to avoid memory leaks
func (m *middleware) Exhaust() *middleware {
	handler := m.Handler
	m.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
		Exhaust(r)
	})
	return m
}

// Methods check the request method is supported
func (m *middleware) Methods(headers, origins []string, methods ...string) *middleware {
	handler := m.Handler
	chainedMethods := strings.Join(methods, ", ") + ", OPTIONS"
	chainedHeaders := strings.Join(headers, ", ") + ", Credentials"
	m.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			addCORS(w, r, chainedMethods, chainedHeaders, origins)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		for _, method := range methods {
			if r.Method == method {
				addCORS(w, r, chainedMethods, chainedHeaders, origins)
				handler.ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, fmt.Sprintf("Unsupported method %s", r.Method), http.StatusBadRequest)
	})
	return m
}

func addCORS(w http.ResponseWriter, r *http.Request, methods string, headers string, origins []string) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return
	}
	match := false
	switch {
	// Always match the current host, either http or https
	case strings.HasPrefix(origin, "https://") && origin[8:] == r.Host:
		match = true
	case strings.HasPrefix(origin, "http://") && origin[7:] == r.Host:
		match = true
	default:
		for _, allowed := range origins {
			if origin == allowed {
				match = true
				break
			}
		}
	}
	if match {
		w.Header().Add("Vary", "Origin")
		w.Header().Add("Access-Control-Allow-Methods", methods)
		w.Header().Add("Access-Control-Allow-Headers", headers)
		w.Header().Add("Access-Control-Expose-Headers", headers)
		w.Header().Add("Access-Control-Allow-Origin", origin)
		w.Header().Add("Access-Control-Allow-Credentials", "true")
	}
}

// Exhaust the request body
func Exhaust(r *http.Request) {
	if r.Body != nil {
		io.Copy(ioutil.Discard, r.Body)
		r.Body.Close()
	}
}
