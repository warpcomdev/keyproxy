package main

import (
	"context"
	htmlTemplate "html/template"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/masterminds/sprig"
	log "github.com/sirupsen/logrus"
)

// Paths that trigger server routines
const (
	RESOURCEPATH = "/resources/"
	LOGINPATH    = "/podapi/login"
	LOGOUTPATH   = "/podapi/logout"
	HEALTHZPATH  = "/healthz"
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
	LoginTemplate = "loginPage.html"
)

// Session Cookie name
const SESSIONCOOKIE = "KEYPROXY_SESSION"

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
	Realm         string
	Resources     fs.FS
	Api           *KubeAPI
	Auth          *AuthManager
	Factory       *PodFactory
	templateGroup *htmlTemplate.Template
	*http.ServeMux
}

// NewServer creates new roxy handler
func NewServer(logger *log.Logger, realm string, resources fs.FS, api *KubeAPI, auth *AuthManager, factory *PodFactory) (*ProxyHandler, error) {
	templateGroup, err := htmlTemplate.New(SpawnTemplate).Funcs(sprig.FuncMap()).ParseFS(resources, "*.html")
	if err != nil {
		logger.WithError(err).Error("Failed to load templates")
		return nil, err
	}
	handler := &ProxyHandler{
		Logger:        logger,
		Realm:         realm,
		Resources:     resources,
		Api:           api,
		Auth:          auth,
		Factory:       factory,
		templateGroup: templateGroup,
		ServeMux:      http.NewServeMux(),
	}
	handler.Handle(RESOURCEPATH, http.StripPrefix(RESOURCEPATH, http.FileServer(http.FS(resources))))
	handler.Handle(LOGINPATH, Middleware(handler.login).Methods(http.MethodGet, http.MethodPost).Exhaust())
	handler.Handle(LOGOUTPATH, Middleware(handler.logout).Auth(handler.Check).Methods(http.MethodGet).Exhaust())
	handler.Handle(HEALTHZPATH, Middleware(handler.healthz).Methods(http.MethodGet).Exhaust())
	handler.Handle(ERRORPATH, Middleware(handler.errorPage).Auth(handler.Check).Methods(http.MethodGet).Exhaust())
	handler.Handle(KILLPATH, Middleware(handler.killPage).Auth(handler.Check).Methods(http.MethodGet).Exhaust())
	handler.Handle(SPAWNPATH, Middleware(handler.spawnPage).Auth(handler.Check).Methods(http.MethodGet).Exhaust())
	handler.Handle(WAITPATH, Middleware(handler.waitPage).Auth(handler.Check).Methods(http.MethodGet).Exhaust())
	handler.Handle("/", Middleware(handler.forward).Auth(handler.Check)) // do not exhaust, in case it upgrades to websocket
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
	contextLog := h.Logger.WithField("cred", cred)
	manager, err := h.Factory.Find(h.Api, cred)
	if err != nil {
		contextLog.WithError(err).Error("Failed to create pod manager")
		return nil, err
	}
	session := Session{
		Credentials: cred,
		AuthSession: authSession,
		Manager:     manager,
		Logger:      contextLog,
	}
	return context.WithValue(ctx, SessionKeyType(0), session), nil
}

// Handle login path
func (h *ProxyHandler) login(w http.ResponseWriter, r *http.Request) {
	h.Logger.Debug("Triggering Login Path")
	if r.Method == http.MethodPost {
		h.Logger.Debug("Triggering login POST path")
		h.LoginForm(w, r)
		return
	}
	h.Logger.Debug("Triggering login GET path")
	h.loginPage(w, r, "")
}

// Parameters passed to login page template
type LoginParams struct {
	Message string
}

// loginPage renders the login page template
func (h *ProxyHandler) loginPage(w http.ResponseWriter, r *http.Request, msg string) {
	if err := h.templateGroup.ExecuteTemplate(w, LoginTemplate, LoginParams{Message: msg}); err != nil {
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

	// Check if parameters are empty
	if cred.Service == "" || cred.Username == "" || pass == "" {
		h.loginPage(w, r, "Empty service name, user or password")
		return
	}
	loggerCtx := h.Logger.WithFields(log.Fields{"service": cred.Service, "username": cred.Username})

	// Get session and check parameters
	session, err := h.Auth.Login(cred, pass)
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

	// Get the jwt token from the session
	token, exp, err := session.JWT()
	if err != nil {
		loggerCtx.WithError(err).Error("Failed to retrieve JWT token")
		h.loginPage(w, r, err.Error())
		return
	}
	if token == "" {
		loggerCtx.Error("Empty token")
		h.loginPage(w, r, "Internal error (empty token)")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     SESSIONCOOKIE,
		Value:    token,
		Expires:  exp,
		Path:     "/",
		HttpOnly: true,
	})
	// Redirect with "SeeOther" to turn POST into GET
	http.Redirect(w, r, "/", http.StatusSeeOther)
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
	h.Logger.Debug("Triggering healthz handler")
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
func (h *ProxyHandler) errorPage(w http.ResponseWriter, r *http.Request) {
	h.Logger.Debug("Triggering Error Page")
	session := r.Context().Value(SessionKeyType(0)).(Session)
	h.render(session.Logger, w, r, session.Manager, session.Credentials, ErrorTemplate, false /*, true*/)
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
	h.render(session.Logger, w, r, session.Manager, session.Credentials, KillTemplate, false /*, false*/)
}

// spawnPage renders the spawn page template
func (h *ProxyHandler) spawnPage(w http.ResponseWriter, r *http.Request) {
	h.Logger.Debug("Triggering Spawn Page")
	session := r.Context().Value(SessionKeyType(0)).(Session)
	h.render(session.Logger, w, r, session.Manager, session.Credentials, SpawnTemplate, true /*, false*/)
}

// waitPage renders the wait page template
func (h *ProxyHandler) waitPage(w http.ResponseWriter, r *http.Request) {
	h.Logger.Debug("Triggering Wait Page")
	session := r.Context().Value(SessionKeyType(0)).(Session)
	h.render(session.Logger, w, r, session.Manager, session.Credentials, WaitTemplate, false /*, true*/)
}

// forward to backend proxy by default
func (h *ProxyHandler) forward(w http.ResponseWriter, r *http.Request) {
	h.Logger.WithField("path", r.URL.Path).Debug("Triggering Proxy")
	session := r.Context().Value(SessionKeyType(0)).(Session)
	proxy, info, err := session.Manager.Proxy(r.Context(), h.Api, false)
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
		redirectPath := WAITPATH
		if info.Type == Deleted || info.Phase == PodFailed || info.Phase == PodSucceeded || info.Phase == PodUnknown {
			redirectPath = ERRORPATH
		}
		http.Redirect(w, r, redirectPath, http.StatusTemporaryRedirect)
		Exhaust(r)
		return
	}
	// TODO: Only change proxy session when actually needed
	proxy.CurrentSession(session.AuthSession)
	proxy.ServeHTTP(w, r)
}

// TemplateParams contains all the parameters available to templates
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

// Render a template
func (h *ProxyHandler) render(logger *log.Entry, w http.ResponseWriter, r *http.Request, mgr *PodManager, cred Credentials, name string, create bool /*, redirect bool*/) {
	logger = logger.WithField("template", name)
	/*proxy*/ _, info, err := mgr.Proxy(r.Context(), h.Api, create)
	if err != nil {
		logger.WithError(err).Error("Failed to get current pod status")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// If already available, redirect
	/*if redirect && info.Type != Deleted && info.Phase == PodRunning && info.Address != "" && proxy != nil {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}*/
	w.Header().Add(http.CanonicalHeaderKey("Content-Type"), "text/html; encoding=utf-8")
	w.WriteHeader(http.StatusOK)
	params := NewParams(cred, info)
	if err := h.templateGroup.ExecuteTemplate(w, name, params); err != nil {
		logger.WithField("params", params).WithError(err).Error("Failed to render template")
	}
}
