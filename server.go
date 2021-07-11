package main

import (
	"fmt"
	htmlTemplate "html/template"
	"io"
	"io/fs"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/masterminds/sprig"
	log "github.com/sirupsen/logrus"
)

// Paths that trigger server routines
const (
	RESOURCEPATH = "/resources"
	ERRORPATH    = "/podapi/error"
	KILLPATH     = "/podapi/kill"
	SPAWNPATH    = "/podapi/spawn"
	WAITPATH     = "/podapi/wait"
)

// Templates for each feedback page
const (
	ErrorTemplate = "errorPage.html"
	KillTemplate  = "killPage.html"
	SpawnTemplate = "spawnPage.html"
	WaitTemplate  = "waitPage.html"
)

// TemplateParams contains all the parameters available to templates
type TemplateParams struct {
	Service   string
	Username  string
	EventType string
	PodPhase  string
	Address   string
}

// ProxyHandler manages the pod lifecycle requests and proxies other requests.
type ProxyHandler struct {
	// lastHealth must be first because it is atomic
	lastHealth AtomicTimestamp
	TimeKeeper
	Logger          *log.Logger
	Realm           string
	Resources       fs.FS
	Api             *KubeAPI
	Auth            *AuthManager
	Factory         *PodFactory
	resourceHandler http.Handler
	templateGroup   *htmlTemplate.Template
}

// NewServer creates new roxy handler
func NewServer(logger *log.Logger, realm string, resources fs.FS, api *KubeAPI, auth *AuthManager, factory *PodFactory) (*ProxyHandler, error) {
	templateGroup, err := htmlTemplate.New(SpawnTemplate).Funcs(sprig.FuncMap()).ParseFS(resources, "*.html")
	if err != nil {
		logger.WithError(err).Error("Failed to load templates")
		return nil, err
	}
	handler := &ProxyHandler{
		Logger:          logger,
		Realm:           realm,
		Resources:       resources,
		Api:             api,
		Auth:            auth,
		Factory:         factory,
		resourceHandler: http.StripPrefix(RESOURCEPATH, http.FileServer(http.FS(resources))),
		templateGroup:   templateGroup,
	}
	handler.Tick(time.Second)
	return handler, nil
}

// Exhaust the request body to avoid men leaks
func (h *ProxyHandler) exhaust(r *http.Request) {
	if r.Body != nil {
		io.Copy(ioutil.Discard, r.Body)
		r.Body.Close()
	}
}

// unauth returns 401 with proper headers
func (h *ProxyHandler) unauth(r *http.Request, w http.ResponseWriter, msg string) {
	w.Header().Add(http.CanonicalHeaderKey("WWW-Authenticate"), fmt.Sprintf("Basic realm=%s", h.Realm))
	http.Error(w, "Missing auth credentials", http.StatusUnauthorized)
	h.exhaust(r)
}

// ServeHTTP implements http.Handler
func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	// Check healthz
	if r.Method == http.MethodGet && r.URL.Path == "/healthz" {
		h.healthz(w, r)
		return
	}

	// Extract service, username and pass from basic auth
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
	cred := Credentials{
		Service:  strings.TrimSpace(part[0]),
		Username: strings.TrimSpace(part[1]),
	}
	pass = strings.TrimSpace(pass)
	if cred.Service == "" || cred.Username == "" || pass == "" {
		h.unauth(r, w, "Empty service name, user or password")
		return
	}

	// Check auth credentials
	session, err := h.Auth.Login(cred, pass, cred.Hash(pass))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		h.exhaust(r)
		return
	}
	if session == nil {
		h.unauth(r, w, "Wrong authorization credentials")
		return
	}

	// Get PodManager
	if strings.HasPrefix(r.URL.Path, RESOURCEPATH) {
		contextLog.Debug("Triggering resource path")
		h.resourceHandler.ServeHTTP(w, r)
		return
	}
	manager, err := h.Factory.Find(h.Api, cred)
	if err != nil {
		contextLog.WithError(err).Error("Failed to get PodManager")
		http.Error(w, "Failed to get PodManager", http.StatusInternalServerError)
		h.exhaust(r)
		return
	}

	// Intercept API paths
	if r.Method == http.MethodGet {
		if strings.HasPrefix(r.URL.Path, ERRORPATH) {
			contextLog.Debug("Triggering error path")
			h.errorPage(contextLog, w, r, manager, cred)
			return
		}
		if strings.HasPrefix(r.URL.Path, KILLPATH) {
			contextLog.Debug("Triggering kill path")
			h.killPage(contextLog, w, r, manager, cred)
			return
		}
		if strings.HasPrefix(r.URL.Path, SPAWNPATH) {
			contextLog.Debug("Triggering spawn path")
			h.spawnPage(contextLog, w, r, manager, cred)
			return
		}
		if strings.HasPrefix(r.URL.Path, WAITPATH) {
			contextLog.Debug("Triggering wait path")
			h.waitPage(contextLog, w, r, manager, cred)
			return
		}
	}

	// By default, proxy to backend
	proxy, info, err := manager.Proxy(r.Context(), h.Api, false)
	if err != nil {
		contextLog.WithError(err).Error("Failed to get pod status")
		http.Error(w, "Failed to get pod status", http.StatusInternalServerError)
		h.exhaust(r)
		return
	}
	if proxy == nil {
		// Redirct only root path, to avoid returning text/html when
		// the client requests other resources, like css, js, etc.
		if r.Method == http.MethodGet && r.URL.Path != "/" {
			http.Error(w, "Pod IP not found", http.StatusNotFound)
			h.exhaust(r)
			return
		}
		redirectPath := WAITPATH
		if info.Type == Deleted || info.Phase == PodFailed || info.Phase == PodSucceeded || info.Phase == PodUnknown {
			redirectPath = ERRORPATH
		}
		http.Redirect(w, r, redirectPath, http.StatusTemporaryRedirect)
		h.exhaust(r)
		return
	}
	proxy.ServeHTTP(w, r)
}

func (h *ProxyHandler) healthz(w http.ResponseWriter, r *http.Request) {
	// Rate limit health cheks to avoid abuse
	lastHealth := h.lastHealth.Load()
	timestamp := h.Clock()
	if lastHealth >= timestamp {
		http.Error(w, "Rate limit health checks", http.StatusInternalServerError)
		h.exhaust(r)
		return
	}
	h.lastHealth.Store(timestamp)
	// Check kubernetes connection
	version, err := h.Api.client.ServerVersion()
	if err != nil {
		h.Logger.WithError(err).Error("Failed health check")
		http.Error(w, "Failed health check", http.StatusInternalServerError)
	} else {
		w.Header().Add(http.CanonicalHeaderKey("Content-Type"), "text/plain; encoding=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(version.String()))
	}
	h.exhaust(r)
}

func NewParams(cred Credentials, info PodInfo) TemplateParams {
	return TemplateParams{
		Service:   cred.Service,
		Username:  cred.Username,
		EventType: string(info.Type),
		PodPhase:  string(info.Phase),
		Address:   info.Address,
	}
}

// Render a template
func (h *ProxyHandler) render(logger *log.Entry, w http.ResponseWriter, r *http.Request, mgr *PodManager, cred Credentials, name string, create bool, redirect bool) {
	defer h.exhaust(r)
	logger = logger.WithField("template", name)
	proxy, info, err := mgr.Proxy(r.Context(), h.Api, create)
	if err != nil {
		logger.WithError(err).Error("Failed to get current pod status")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// If already available, redirect
	if redirect && info.Type != Deleted && info.Phase == PodRunning && info.Address != "" && proxy != nil {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	w.Header().Add(http.CanonicalHeaderKey("Content-Type"), "text/html; encoding=utf-8")
	w.WriteHeader(http.StatusOK)
	params := NewParams(cred, info)
	if err := h.templateGroup.ExecuteTemplate(w, name, params); err != nil {
		logger.WithField("params", params).WithError(err).Error("Failed to render template")
	}
}

func (h *ProxyHandler) errorPage(logger *log.Entry, w http.ResponseWriter, r *http.Request, mgr *PodManager, cred Credentials) {
	h.render(logger, w, r, mgr, cred, ErrorTemplate, false, true)
}

func (h *ProxyHandler) killPage(logger *log.Entry, w http.ResponseWriter, r *http.Request, mgr *PodManager, cred Credentials) {
	if err := mgr.Delete(r.Context(), h.Api); err != nil {
		logger.WithError(err).Error("Failed to kill pod")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		h.exhaust(r)
		return
	}
	h.render(logger, w, r, mgr, cred, KillTemplate, false, false)
}

func (h *ProxyHandler) spawnPage(logger *log.Entry, w http.ResponseWriter, r *http.Request, mgr *PodManager, cred Credentials) {
	h.render(logger, w, r, mgr, cred, SpawnTemplate, true, false)
}

func (h *ProxyHandler) waitPage(logger *log.Entry, w http.ResponseWriter, r *http.Request, mgr *PodManager, cred Credentials) {
	h.render(logger, w, r, mgr, cred, WaitTemplate, false, true)
}
