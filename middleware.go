package main

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
)

type middleware struct {
	http.Handler
}

func Middleware(handlerFunc func(w http.ResponseWriter, r *http.Request)) *middleware {
	return &middleware{
		Handler: http.HandlerFunc(handlerFunc),
	}
}

// Auth checks authentication and stores session in context.
func (m *middleware) Auth(check func(ctx context.Context, token string) (context.Context, error)) *middleware {
	handler := m.Handler
	m.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Use different redirect code depending on the method
		statusRedirect := http.StatusTemporaryRedirect
		if r.Method != http.MethodGet {
			statusRedirect = http.StatusSeeOther
		}

		// Check if cookie exists
		var authCookie *http.Cookie
		cookies := r.Cookies()
		for _, cookie := range cookies {
			if cookie.Name == SESSIONCOOKIE {
				authCookie = cookie
				break
			}
		}
		if authCookie == nil {
			http.Redirect(w, r, LOGINPATH, statusRedirect)
			return
		}

		// Check cookie credentials
		ctx, err := check(r.Context(), authCookie.Value)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if ctx == nil {
			http.Redirect(w, r, LOGINPATH, statusRedirect)
			return
		}
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
	return m
}

// Exhaust the request body to avoid men leaks
func (m *middleware) Exhaust() *middleware {
	handler := m.Handler
	m.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
		Exhaust(r)
	})
	return m
}

// methods check the request method is supported
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
