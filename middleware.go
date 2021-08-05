package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	log "github.com/sirupsen/logrus"
)

type middleware struct {
	http.Handler
}

// Middleware constructor facilitates chaining middlewares
func Middleware(handlerFunc func(w http.ResponseWriter, r *http.Request)) *middleware {
	return &middleware{
		Handler: http.HandlerFunc(handlerFunc),
	}
}

// Auth checks authentication and stores session in context.
func (m *middleware) Auth(cookieName string, check func(ctx context.Context, token string) (context.Context, error), redirectAlways bool) *middleware {
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
			if redirectAlways || (r.URL.Path == "/" && r.Method == http.MethodGet) {
				redirectPath := fmt.Sprintf("https://%s%s", r.URL.Host, LOGINPATH)
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
func (m *middleware) Methods(methods ...string) *middleware {
	handler := m.Handler
	m.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, method := range methods {
			if r.Method == method {
				handler.ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, fmt.Sprintf("Unsupported method %s", r.Method), http.StatusBadRequest)
	})
	return m
}

// Exhaust the request body
func Exhaust(r *http.Request) {
	if r.Body != nil {
		io.Copy(ioutil.Discard, r.Body)
		r.Body.Close()
	}
}
