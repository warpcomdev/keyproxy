package main

import (
	"embed"
	"fmt"
	htmlTemplate "html/template"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	KILLPATH     = "/kill"
	RESOURCEPATH = "/resources"
)

//go:embed resources/*
var resources embed.FS

type rootHandler struct {
	Resources       *embed.FS
	Logger          *log.Logger
	Realm           string
	proxy           *httputil.ReverseProxy
	killPage        *htmlTemplate.Template
	resourceHandler http.Handler
}

// Exhaust the request body to avoid men leaks
func (h *rootHandler) exhaust(r *http.Request) {
	if r.Body != nil {
		io.Copy(ioutil.Discard, r.Body)
		r.Body.Close()
	}
}

func (h *rootHandler) unauth(r *http.Request, w http.ResponseWriter, msg string) {
	h.exhaust(r)
	w.Header().Add("WWW-Authenticate", fmt.Sprintf("Basic realm=%s", h.Realm))
	http.Error(w, "Missing auth credentials", http.StatusUnauthorized)
}

func (h *rootHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	user, pass, ok := r.BasicAuth()
	contextLog := h.Logger.WithFields(log.Fields{
		"url":  r.URL.String(),
		"user": user,
	})
	if !ok {
		h.unauth(r, w, "Missing auth credentials")
		return
	}
	if !strings.Contains(user, "/") {
		h.unauth(r, w, "Missing service name")
		return
	}
	part := strings.SplitN(user, "/", 2)
	serv := strings.TrimSpace(part[0])
	user = strings.TrimSpace(part[1])
	pass = strings.TrimSpace(pass)
	if serv == "" || user == "" || pass == "" {
		h.unauth(r, w, "Empty service name, user or password")
		return
	}
	ok, err := Auth(contextLog, serv, user, pass)
	if !ok {
		h.unauth(r, w, "Wrong authorization credentials")
		return
	}
	if err != nil {
		h.exhaust(r)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if strings.HasPrefix(r.URL.Path, KILLPATH) {
		contextLog.Debug("Triggering kill path")
		h.kill(contextLog, r, w, serv, user)
		return
	}
	if strings.HasPrefix(r.URL.Path, RESOURCEPATH) {
		contextLog.Debug("Triggering resource path")
		h.exhaust(r)
		if h.resourceHandler == nil {
			if h.Resources == nil {
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}
			h.resourceHandler = http.FileServer(http.FS(h.Resources))
		}
		h.resourceHandler.ServeHTTP(w, r)
		return
	}
	h.proxy.ServeHTTP(w, r)
}

type Credentials struct {
	Service  string
	Username string
}

func (h *rootHandler) kill(logger *log.Entry, r *http.Request, w http.ResponseWriter, serv, user string) {
	h.exhaust(r)
	w.WriteHeader(http.StatusOK)
	if h.killPage == nil {
		logger.Debug("Loading template killPage.html")
		killPage, err := htmlTemplate.ParseFS(h.Resources, "resources/killPage.html")
		if err != nil {
			logger.WithError(err).Error("Failed to load killPage template")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		h.killPage = killPage
	}
	if err := h.killPage.Execute(w, Credentials{Service: serv, Username: user}); err != nil {
		logger.WithError(err).Error("Failed to render killPage template")
	}
}

func proxyFor(backend string) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(backend)
	if err != nil {
		return nil, err
	}
	tp := httputil.NewSingleHostReverseProxy(target)
	return tp, nil
}

func main() {

	logger := log.New()
	logger.Level = log.DebugLevel
	logger.Out = os.Stdout

	proxy, err := proxyFor("http://localhost:9390")
	if err != nil {
		panic(err)
	}
	srv := &http.Server{
		Addr: ":8080",
		Handler: &rootHandler{
			proxy:     proxy,
			Resources: &resources,
			Logger:    logger,
			Realm:     "Keyproxy Auth",
		},
	}
	if err := srv.ListenAndServe(); err != nil {
		panic(err)
	}
}
