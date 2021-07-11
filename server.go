package main

import (
	htmlTemplate "html/template"
	"io"
	"io/fs"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
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
	LOGINPATH    = "/podapi/login"
	LOGOUTPATH   = "/podapi/logout"
)

// Session Cookie name
const SESSIONCOOKIE = "KEYPROXY_SESSION"

// Templates for each feedback page
const (
	ErrorTemplate = "errorPage.html"
	KillTemplate  = "killPage.html"
	SpawnTemplate = "spawnPage.html"
	WaitTemplate  = "waitPage.html"
	LoginTemplate = "loginPage.html"
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
	SigningKey      []byte
	Resources       fs.FS
	Api             *KubeAPI
	Auth            *AuthManager
	Factory         *PodFactory
	resourceHandler http.Handler
	templateGroup   *htmlTemplate.Template
}

type CustomClaims struct {
	jwt.StandardClaims
	Service  string
	Username string
	Hash     uint32
}

// NewServer creates new roxy handler
func NewServer(logger *log.Logger, realm string, signingKey []byte, resources fs.FS, api *KubeAPI, auth *AuthManager, factory *PodFactory) (*ProxyHandler, error) {
	templateGroup, err := htmlTemplate.New(SpawnTemplate).Funcs(sprig.FuncMap()).ParseFS(resources, "*.html")
	if err != nil {
		logger.WithError(err).Error("Failed to load templates")
		return nil, err
	}
	handler := &ProxyHandler{
		Logger:          logger,
		Realm:           realm,
		SigningKey:      signingKey,
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

// ServeHTTP implements http.Handler
func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	// Check unprotected paths: /healthz and /resources
	if strings.HasPrefix(r.URL.Path, RESOURCEPATH) {
		h.Logger.Debug("Triggering resource path")
		h.resourceHandler.ServeHTTP(w, r)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/healthz" {
		h.Logger.Debug("Triggering healthz path")
		h.healthz(w, r)
		return
	}

	// Handle login path
	if strings.HasPrefix(r.URL.Path, LOGINPATH) {
		if r.Method == http.MethodGet {
			h.Logger.Debug("Triggering login GET path")
			h.loginPage(w, r, "")
			return
		}
		if r.Method == http.MethodPost {
			h.Logger.Debug("Triggering login POST path")
			h.LoginForm(w, r)
			return
		}
		http.Error(w, "Unsupported HTTP Method", http.StatusBadRequest)
		h.exhaust(r)
		return
	}

	// Other than that, paths are authenticated by cookie.
	var authCookie *http.Cookie
	cookies := r.Cookies()
	for _, cookie := range cookies {
		if cookie.Name == SESSIONCOOKIE {
			authCookie = cookie
			break
		}
	}
	if authCookie == nil {
		h.Logger.Debug("No cookie received, redirecto to login page")
		http.Redirect(w, r, LOGINPATH, http.StatusTemporaryRedirect)
		h.exhaust(r)
		return
	}

	// Check cookie credentials
	authCred, authSession, err := h.CheckCookie(authCookie)
	if authSession == nil || err != nil {
		h.Logger.Debug("Cookie is not valid, redirect to login page")
		http.Redirect(w, r, LOGINPATH, http.StatusTemporaryRedirect)
		h.exhaust(r)
		return
	}

	// If authenticated, check logout path
	if strings.HasPrefix(r.URL.Path, LOGOUTPATH) && r.Method == http.MethodGet {
		h.Logger.Debug("Triggering LOGOUT GET Path")
		h.Auth.Logout(authSession)
		http.SetCookie(w, &http.Cookie{Name: SESSIONCOOKIE, Value: ""})
		http.Redirect(w, r, LOGINPATH, http.StatusTemporaryRedirect)
		h.exhaust(r)
	}

	// Get PodManager
	contextLog := h.Logger.WithField("cred", authCred)
	manager, err := h.Factory.Find(h.Api, authCred)
	if err != nil {
		contextLog.WithError(err).Error("Failed to get PodManager")
		http.Error(w, "Failed to get PodManager", http.StatusInternalServerError)
		h.exhaust(r)
		return
	}

	// Intercept API paths
	contextLog.WithFields(log.Fields{"method": r.Method, "path": r.URL.Path}).Debug("Routing request")
	if r.Method == http.MethodGet {
		if strings.HasPrefix(r.URL.Path, ERRORPATH) {
			contextLog.Debug("Triggering error path")
			h.errorPage(contextLog, w, r, manager, authCred)
			return
		}
		if strings.HasPrefix(r.URL.Path, KILLPATH) {
			contextLog.Debug("Triggering kill path")
			h.killPage(contextLog, w, r, manager, authCred)
			return
		}
		if strings.HasPrefix(r.URL.Path, SPAWNPATH) {
			contextLog.Debug("Triggering spawn path")
			h.spawnPage(contextLog, w, r, manager, authCred)
			return
		}
		if strings.HasPrefix(r.URL.Path, WAITPATH) {
			contextLog.Debug("Triggering wait path")
			h.waitPage(contextLog, w, r, manager, authCred)
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
		// Redirect only root path, to avoid returning text/html when
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
	// TODO: Refresh cookie in response headers
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

// LoginForm processes the login form and sets a cookie
func (h *ProxyHandler) LoginForm(w http.ResponseWriter, r *http.Request) {

	// Get credentials
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form data", http.StatusBadRequest)
		h.exhaust(r)
		return
	}
	cred := Credentials{
		Service:  strings.TrimSpace(r.Form.Get("service")),
		Username: strings.TrimSpace(r.Form.Get("username")),
	}
	pass := strings.TrimSpace(r.Form.Get("password"))

	// Check if parameters are empty
	if cred.Service == "" || cred.Username == "" || pass == "" {
		h.loginPage(w, r, "Empty service name, user or password")
		return
	}
	loggerCtx := h.Logger.WithFields(log.Fields{"service": cred.Service, "username": cred.Username})

	// Get session and check parameters
	session, err := h.Auth.Login(cred, pass, 0)
	if err != nil {
		loggerCtx.WithError(err).Error("Failed to login")
		h.loginPage(w, r, err.Error())
		return
	}
	if session == nil {
		loggerCtx.Info("Wrong credentials")
		h.loginPage(w, r, "Wrong credentials")
		return
	}

	// If authentication succeeds, create token
	loggerCtx.Info("Authentication succeeded")
	// TODO: Add timestamps to claims
	claims := CustomClaims{
		Service:  cred.Service,
		Username: cred.Username,
		Hash:     session.Hash,
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims).SignedString(h.SigningKey)
	if err != nil {
		loggerCtx.WithError(err).Error("Failed to sign token")
		h.loginPage(w, r, err.Error())
		return
	}

	// Set the cookie and go for the home page
	loggerCtx.WithFields(log.Fields{"claims": claims, "token": token}).Debug("Storing JWT token in cookie")
	http.SetCookie(w, &http.Cookie{
		Name:    SESSIONCOOKIE,
		Value:   token,
		Expires: session.Expiration,
		Path:    "/",
	})
	// Redirect with "SeeOther" to turn POST into GET
	http.Redirect(w, r, "/", http.StatusSeeOther)
	h.exhaust(r)
}

func (h *ProxyHandler) CheckCookie(cookie *http.Cookie) (Credentials, *AuthSession, error) {
	var claims CustomClaims
	token, err := jwt.ParseWithClaims(cookie.Value, &claims, func(token *jwt.Token) (interface{}, error) {
		return h.SigningKey, nil
	})
	if err != nil || !token.Valid {
		h.Logger.WithError(err).Error("Failed to parse token")
		return Credentials{}, nil, err
	}
	// TODO: Check cookie and token expirations
	loggerCtx := h.Logger.WithFields(log.Fields{
		"service":  claims.Service,
		"username": claims.Username,
		"hash":     claims.Hash,
	})
	creds := Credentials{
		Service:  claims.Service,
		Username: claims.Username,
	}
	session, err := h.Auth.Check(creds, claims.Hash)
	if err != nil {
		loggerCtx.WithError(err).Error("Error while getting session")
		return creds, nil, err
	}
	if session == nil {
		loggerCtx.WithError(err).Error("Logging session not found")
		return creds, nil, nil
	}
	return creds, session, nil
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

type LoginParams struct {
	Message string
}

func (h *ProxyHandler) loginPage(w http.ResponseWriter, r *http.Request, msg string) {
	defer h.exhaust(r)
	if err := h.templateGroup.ExecuteTemplate(w, LoginTemplate, LoginParams{Message: msg}); err != nil {
		h.Logger.WithError(err).Error("Failed to render login template")
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
