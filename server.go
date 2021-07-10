package main

import (
	"fmt"
	htmlTemplate "html/template"
	"io"
	"io/fs"
	"io/ioutil"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
)

type rootHandler struct {
	Logger          *log.Logger
	Realm           string
	Resources       fs.FS
	Api             *KubeAPI
	Factory         *PodFactory
	resourceHandler http.Handler
	templateGroup   *htmlTemplate.Template
}

const (
	RESOURCEPATH = "/resources"
	ERRORPATH    = "/poderror"
	KILLPATH     = "/podkill"
	SPAWNPATH    = "/podspawn"
	WAITPATH     = "/podwait"

	ErrorTemplate = "errorPage.html"
	KillTemplate  = "killPage.html"
	SpawnTemplate = "spawnPage.html"
	WaitTemplate  = "waitPage.html"
)

func NewServer(logger *log.Logger, realm string, resources fs.FS, api *KubeAPI, factory *PodFactory) (*rootHandler, error) {
	templateGroup, err := htmlTemplate.New(SpawnTemplate).ParseFS(resources, "*.html")
	if err != nil {
		logger.WithError(err).Error("Failed to load templates")
		return nil, err
	}
	return &rootHandler{
		Logger:          logger,
		Realm:           realm,
		Resources:       resources,
		Api:             api,
		Factory:         factory,
		resourceHandler: http.StripPrefix(RESOURCEPATH, http.FileServer(http.FS(resources))),
		templateGroup:   templateGroup,
	}, nil
}

// Exhaust the request body to avoid men leaks
func (h *rootHandler) exhaust(r *http.Request) {
	if r.Body != nil {
		io.Copy(ioutil.Discard, r.Body)
		r.Body.Close()
	}
}

func (h *rootHandler) unauth(r *http.Request, w http.ResponseWriter, msg string) {
	w.Header().Add("WWW-Authenticate", fmt.Sprintf("Basic realm=%s", h.Realm))
	http.Error(w, "Missing auth credentials", http.StatusUnauthorized)
	h.exhaust(r)
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
	cred := Credentials{
		Service:  strings.TrimSpace(part[0]),
		Username: strings.TrimSpace(part[1]),
	}
	pass = strings.TrimSpace(pass)
	if cred.Service == "" || cred.Username == "" || pass == "" {
		h.unauth(r, w, "Empty service name, user or password")
		return
	}
	ok, err := Auth(contextLog, cred, pass)
	if !ok {
		h.unauth(r, w, "Wrong authorization credentials")
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		h.exhaust(r)
		return
	}
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
	proxy, info, err := manager.Proxy(r.Context(), h.Api, false)
	if err != nil {
		contextLog.WithError(err).Error("Failed to get pod status")
		http.Error(w, "Failed to get pod status", http.StatusInternalServerError)
		h.exhaust(r)
		return
	}
	if proxy == nil && r.URL.Path != "/" {
		http.Error(w, "Pod IP not found", http.StatusNotFound)
		h.exhaust(r)
		return
	}
	if proxy == nil {
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

type TemplateParams struct {
	Service   string
	Username  string
	EventType string
	PodPhase  string
	Address   string
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

func (h *rootHandler) render(logger *log.Entry, w http.ResponseWriter, r *http.Request, mgr *PodManager, cred Credentials, name string, create bool, redirect bool) {
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

func (h *rootHandler) errorPage(logger *log.Entry, w http.ResponseWriter, r *http.Request, mgr *PodManager, cred Credentials) {
	h.render(logger, w, r, mgr, cred, ErrorTemplate, false, true)
}

func (h *rootHandler) killPage(logger *log.Entry, w http.ResponseWriter, r *http.Request, mgr *PodManager, cred Credentials) {
	if err := mgr.Delete(r.Context(), h.Api); err != nil {
		logger.WithError(err).Error("Failed to kill pod")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		h.exhaust(r)
		return
	}
	h.render(logger, w, r, mgr, cred, KillTemplate, false, false)
}

func (h *rootHandler) spawnPage(logger *log.Entry, w http.ResponseWriter, r *http.Request, mgr *PodManager, cred Credentials) {
	h.render(logger, w, r, mgr, cred, SpawnTemplate, true, false)
}

func (h *rootHandler) waitPage(logger *log.Entry, w http.ResponseWriter, r *http.Request, mgr *PodManager, cred Credentials) {
	h.render(logger, w, r, mgr, cred, WaitTemplate, false, true)
}
