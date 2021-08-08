package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	htmlTemplate "html/template"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/masterminds/sprig"
	log "github.com/sirupsen/logrus"

	// Bring profiling interface in
	_ "net/http/pprof"
)

// Paths that trigger server routines
const (
	RESOURCEPATH = "/resources/"
	LOGINPATH    = "/podapi/login"
	LOGOUTPATH   = "/podapi/logout"
	HEALTHZPATH  = "/healthz"
	KILLPATH     = "/podapi/kill"
	SPAWNPATH    = "/podapi/spawn"
	INFOPATH     = "/podapi/info"
)

// Templates for each feedback page
const (
	ErrorTemplate = "errorPage.html"
	KillTemplate  = "killPage.html"
	SpawnTemplate = "spawnPage.html"
	WaitTemplate  = "waitPage.html"
	LoginTemplate = "loginPage.html"
)

// Session Cookie name
const SESSIONCOOKIE = "KEYPROXY_SESSION"

// CSRF Cookie name
const CSRFCOOKIE = "KEYPROXY_CSRF"

// AuthSessionKeyType used for storing session in request context.
type SessionKeyType int
type Session struct {
	Credentials Credentials
	AuthSession *AuthSession
	Manager     *PodManager
	Logger      *log.Entry
}

// ProxyHandler manages the pod lifecycle requests and proxies other requests.
type ProxyHandler struct {
	// lastHealth must be first because it is atomic
	lastHealth AtomicTimestamp
	TimeKeeper
	Logger        *log.Logger
	Redirect      string // Where to redirect requests for "/"
	ProxyScheme   string // // scheme for the login page, "http" or "https"
	AppScheme     string // scheme for the app, "http" or "https"
	Resources     fs.FS
	Api           *KubeAPI
	Auth          *AuthManager
	Factory       *PodFactory
	csrfSecret    []byte
	templateGroup *htmlTemplate.Template
	*http.ServeMux
}

// NewServer creates new proxy handler
func NewServer(logger *log.Logger, redirect, proxyscheme, appscheme string, resources fs.FS, api *KubeAPI, auth *AuthManager, factory *PodFactory) (*ProxyHandler, error) {
	templateGroup, err := htmlTemplate.New(SpawnTemplate).Funcs(sprig.FuncMap()).ParseFS(resources, "*.html")
	if err != nil {
		logger.WithError(err).Error("Failed to load templates")
		return nil, err
	}
	handler := &ProxyHandler{
		Logger:        logger,
		Resources:     resources,
		Redirect:      redirect,
		ProxyScheme:   proxyscheme,
		AppScheme:     appscheme,
		Api:           api,
		Auth:          auth,
		Factory:       factory,
		templateGroup: templateGroup,
		csrfSecret:    make([]byte, 64),
		ServeMux:      http.NewServeMux(),
	}
	rand.Read(handler.csrfSecret)
	handler.Handle(RESOURCEPATH, http.StripPrefix(RESOURCEPATH, http.FileServer(http.FS(resources))))
	handler.Handle(LOGINPATH, Middleware(handler.login).Methods(http.MethodGet, http.MethodPost).Exhaust())
	handler.Handle(LOGOUTPATH, Middleware(handler.logout).Auth(handler.ProxyScheme, SESSIONCOOKIE, handler.Check, true).Methods(http.MethodGet).Exhaust())
	handler.Handle(HEALTHZPATH, Middleware(handler.healthz).Methods(http.MethodGet).Exhaust())
	handler.Handle(INFOPATH, Middleware(handler.infoPage).Auth(handler.ProxyScheme, SESSIONCOOKIE, handler.Check, true).Methods(http.MethodGet).Exhaust())
	handler.Handle(KILLPATH, Middleware(handler.killPage).Auth(handler.ProxyScheme, SESSIONCOOKIE, handler.Check, true).Methods(http.MethodGet).Exhaust())
	handler.Handle(SPAWNPATH, Middleware(handler.spawnPage).Auth(handler.ProxyScheme, SESSIONCOOKIE, handler.Check, true).Methods(http.MethodGet).Exhaust())
	handler.Handle("/", Middleware(handler.forward).Auth(handler.ProxyScheme, SESSIONCOOKIE, handler.Check, false)) // do not exhaust, in case it upgrades to websocket
	// Add support for pprof
	handler.Handle("/debug/pprof", http.DefaultServeMux)
	handler.Tick(time.Second)
	return handler, nil
}

// Auth checks authentication and stores session in context
func (h *ProxyHandler) Check(ctx context.Context, token string) (context.Context, error) {
	cred, authSession, err := h.Auth.Check(token)
	if err != nil {
		h.Logger.WithError(err).Info("Failed to validate login")
		return nil, err
	}
	if authSession == nil {
		return nil, err
	}
	logger := h.Logger.WithField("cred", cred)
	mgr, err := h.Factory.Find(h.Api, cred)
	if err != nil {
		logger.WithError(err).Error("Failed to create pod manager")
		return nil, err
	}
	session := Session{
		Credentials: cred,
		AuthSession: authSession,
		Manager:     mgr,
		Logger:      logger,
	}
	return context.WithValue(ctx, SessionKeyType(0), session), nil
}

// Handle login path
func (h *ProxyHandler) login(w http.ResponseWriter, r *http.Request) {
	logger := h.Logger.WithFields(log.Fields{"method": r.Method, "path": r.URL.Path})
	if r.Method == http.MethodPost {
		logger.Debug("Triggering login POST path")
		h.LoginForm(w, r)
		return
	}
	logger.Debug("Triggering login GET path")
	h.loginPage(w, r, Credentials{}, "")
}

// LoginParams passed to login page template
type LoginParams struct {
	ProxyScheme string
	AppScheme   string
	Host        string
	Service     string
	Username    string
	Message     string
	CSRFToken   string
}

// TemplateParams passed to all other template pages
type TemplateParams struct {
	ProxyScheme string
	AppScheme   string
	Host        string
	Service     string
	Username    string
	EventType   EventType
	PodPhase    PodPhase
	Ready       bool
	Address     string
}

// loginPage renders the login page template
func (h *ProxyHandler) loginPage(w http.ResponseWriter, r *http.Request, cred Credentials, msg string) {
	// Create CSRF token
	buffer := make([]byte, 64)
	rand.Read(buffer)
	csrfToken := base64.StdEncoding.EncodeToString(buffer)
	// Sign CSRF token
	mac := hmac.New(sha256.New, h.csrfSecret)
	mac.Write(buffer)
	cookieToken := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	// Save signature as cookie
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCOOKIE,
		Value:    cookieToken,
		Expires:  time.Now().Add(15 * time.Minute),
		Path:     "/",
		HttpOnly: true,
	})
	params := LoginParams{
		ProxyScheme: h.ProxyScheme,
		AppScheme:   h.AppScheme,
		Host:        r.Host,
		Service:     cred.Service,
		Username:    cred.Username,
		Message:     msg,
		CSRFToken:   csrfToken,
	}
	if err := h.templateGroup.ExecuteTemplate(w, LoginTemplate, params); err != nil {
		h.Logger.WithError(err).Error("Failed to render login template")
	}
}

// LoginForm processes the login form and sets a cookie
func (h *ProxyHandler) LoginForm(w http.ResponseWriter, r *http.Request) {

	// Get credentials
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form data", http.StatusBadRequest)
		return
	}
	cred := Credentials{
		Service:  strings.TrimSpace(r.Form.Get("service")),
		Username: strings.TrimSpace(r.Form.Get("username")),
	}
	pass := strings.TrimSpace(r.Form.Get("password"))
	token := strings.TrimSpace(r.Form.Get("csrftoken"))

	// Check if parameters are empty
	if cred.Service == "" || cred.Username == "" || pass == "" || token == "" {
		h.loginPage(w, r, cred, "Empty service name, user, password or token")
		return
	}
	logger := h.Logger.WithFields(log.Fields{"service": cred.Service, "username": cred.Username})

	csrfCookie, err := r.Cookie(CSRFCOOKIE)
	if err != nil && errors.Is(err, http.ErrNoCookie) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		csrfCookie = nil
	}
	if csrfCookie == nil {
		h.loginPage(w, r, cred, "Error while matching request")
		return
	}

	buffer, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		h.loginPage(w, r, cred, err.Error())
		return
	}
	signature, err := base64.StdEncoding.DecodeString(csrfCookie.Value)
	if err != nil {
		h.loginPage(w, r, cred, err.Error())
		return
	}
	mac := hmac.New(sha256.New, h.csrfSecret)
	mac.Write(buffer)
	if bytes.Compare(signature, mac.Sum(nil)) != 0 {
		h.loginPage(w, r, cred, "Error while matching tokens")
	}

	// Get session and check parameters
	session, err := h.Auth.Login(cred, pass)
	if err != nil {
		logger.WithError(err).Error("Failed to login")
		h.loginPage(w, r, cred, err.Error())
		return
	}
	if session == nil {
		logger.Info("Wrong credentials")
		h.loginPage(w, r, cred, "Wrong credentials")
		return
	}

	// Get the jwt token from the session
	token, exp, err := session.JWT()
	if err != nil {
		logger.WithError(err).Error("Failed to retrieve JWT token")
		h.loginPage(w, r, cred, err.Error())
		return
	}
	if token == "" {
		logger.Error("Empty token")
		h.loginPage(w, r, cred, "Internal error (empty token)")
		return
	}

	// Double-check the auth won't fail (it checks a few other things,
	// like the pod watch)
	_, err = h.Check(context.TODO(), token)
	if err != nil {
		logger.WithError(err).Error("Failed to check JWT token")
		h.loginPage(w, r, cred, err.Error())
		return
	}

	// Save JWT token as Cookie
	http.SetCookie(w, &http.Cookie{
		Name:     SESSIONCOOKIE,
		Value:    token,
		Expires:  exp,
		Path:     "/",
		HttpOnly: true,
	})
	// Redirect with "SeeOther" to turn POST into GET
	redirectURL := fmt.Sprintf("%s://%s", h.AppScheme, r.Host)
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

// Handle logout path
func (h *ProxyHandler) logout(w http.ResponseWriter, r *http.Request) {
	h.Logger.Debug("Triggering LOGOUT Path")
	session := r.Context().Value(SessionKeyType(0)).(Session)
	h.Auth.Logout(session.AuthSession)
	http.SetCookie(w, &http.Cookie{Name: SESSIONCOOKIE, Value: ""})
	http.Redirect(w, r, LOGINPATH, http.StatusTemporaryRedirect)
}

// healthz path checks connectivity to kubernetes
func (h *ProxyHandler) healthz(w http.ResponseWriter, r *http.Request) {
	// Rate limit health cheks to avoid abuse
	lastHealth := h.lastHealth.Load()
	timestamp := h.Clock()
	if lastHealth >= timestamp {
		http.Error(w, "Rate limit health checks", http.StatusInternalServerError)
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
}

// errorPage renders the error page template
func (h *ProxyHandler) infoPage(w http.ResponseWriter, r *http.Request) {
	h.Logger.Debug("Triggering Info Page")
	session := r.Context().Value(SessionKeyType(0)).(Session)
	params, err := h.NewParams(r, session, false)
	if err != nil {
		session.Logger.WithError(err).Error("Failed to get current pod info")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	template := WaitTemplate
	if params.EventType == Deleted || params.PodPhase == PodFailed || params.PodPhase == PodSucceeded || params.PodPhase == PodUnknown {
		template = ErrorTemplate
	}
	h.render(session.Logger, w, r, template, params)
}

// killPage renders the kill page template
func (h *ProxyHandler) killPage(w http.ResponseWriter, r *http.Request) {
	h.Logger.Debug("Triggering Kill Page")
	session := r.Context().Value(SessionKeyType(0)).(Session)
	if err := session.Manager.Delete(r.Context(), h.Api); err != nil {
		session.Logger.WithError(err).Error("Failed to kill pod")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	params, err := h.NewParams(r, session, false)
	if err != nil {
		session.Logger.WithError(err).Error("Failed to create params after killing pod")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.render(session.Logger, w, r, KillTemplate, params)
}

// spawnPage renders the spawn page template
func (h *ProxyHandler) spawnPage(w http.ResponseWriter, r *http.Request) {
	h.Logger.Debug("Triggering Spawn Page")
	session := r.Context().Value(SessionKeyType(0)).(Session)
	params, err := h.NewParams(r, session, true)
	if err != nil {
		session.Logger.WithError(err).Error("Failed to spawn pod")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.render(session.Logger, w, r, SpawnTemplate, params)
}

// forward to backend proxy by default
func (h *ProxyHandler) forward(w http.ResponseWriter, r *http.Request) {
	h.Logger.WithField("path", r.URL.Path).Debug("Triggering Proxy")
	session := r.Context().Value(SessionKeyType(0)).(Session)
	proxy, _, err := session.Manager.Proxy(r.Context(), h.Api, false)
	if err != nil {
		session.Logger.WithError(err).Error("Failed to get pod status")
		http.Error(w, "Failed to get pod status", http.StatusInternalServerError)
		return
	}
	if proxy == nil {
		// Redirect only root path, to avoid returning text/html when
		// the client requests other resources, like css, js, etc.
		if r.Method != http.MethodGet || r.URL.Path != "/" {
			http.Error(w, "Pod IP not found", http.StatusNotFound)
			Exhaust(r)
			return
		}
		redirectURL := fmt.Sprintf("%s://%s%s", h.ProxyScheme, r.Host, INFOPATH)
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
		Exhaust(r)
		return
	} else {
		if h.Redirect != "" && r.Method == http.MethodGet && r.URL.Path == "/" {
			http.Redirect(w, r, h.Redirect, http.StatusTemporaryRedirect)
			Exhaust(r)
			return
		}
	}
	// TODO: Only change proxy session when actually needed
	proxy.CurrentSession(session.AuthSession)
	proxy.ServeHTTP(w, r)
}

func (h *ProxyHandler) NewParams(r *http.Request, session Session, create bool) (TemplateParams, error) {
	_, info, err := session.Manager.Proxy(r.Context(), h.Api, create)
	if err != nil {
		return TemplateParams{}, err
	}
	params := TemplateParams{
		ProxyScheme: h.ProxyScheme,
		AppScheme:   h.AppScheme,
		Host:        r.Host,
		Service:     session.Credentials.Service,
		Username:    session.Credentials.Username,
		EventType:   info.Type,
		PodPhase:    info.Phase,
		Address:     info.Address,
		Ready:       info.Ready,
	}
	return params, nil
}

// Render a template
func (h *ProxyHandler) render(logger *log.Entry, w http.ResponseWriter, r *http.Request, name string, params TemplateParams) {
	logger = logger.WithField("template", name)
	w.Header().Add(http.CanonicalHeaderKey("Content-Type"), "text/html; encoding=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := h.templateGroup.ExecuteTemplate(w, name, params); err != nil {
		logger.WithField("params", params).WithError(err).Error("Failed to render template")
	}
}
