package main

import (
	"context"
	"crypto/rand"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"text/template"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/masterminds/sprig"
	log "github.com/sirupsen/logrus"

	"github.com/warpcomdev/keyproxy/internal/auth"
	"github.com/warpcomdev/keyproxy/internal/kube"
	"github.com/warpcomdev/keyproxy/internal/mock"
	"github.com/warpcomdev/keyproxy/internal/server"
)

//go:embed podstatic/*
var podstatic embed.FS

//go:embed templates/*
var templates embed.FS

// localResources checks if there is a local folder with resources.
// Otherwise, it uses the embedded ones.
func localResources(logger *log.Logger, externalDir string, embedded fs.FS, embeddedSub string) fs.FS {
	loggerCtx := logger.WithField("externalDir", externalDir)
	stat, err := os.Stat(externalDir)
	if err != nil {
		if !os.IsNotExist(err) {
			panic(err)
		}
	} else {
		if stat.IsDir() {
			loggerCtx.Info("Using local resources")
			return os.DirFS(externalDir)
		}
	}
	// Use embedded resources, but strip prefix to match
	// the local dir use case.
	loggerCtx.Info("Using embedded resources")
	sub, err := fs.Sub(embedded, embeddedSub)
	if err != nil {
		panic(err)
	}
	return sub
}

func main() {

	logger := log.New()
	logger.Level = log.DebugLevel
	logger.Out = os.Stdout
	config := GetConfig()

	logger.WithFields(log.Fields{"podconfig": config.PodConfig}).Info("Reading pod template")
	tmpl, err := template.New(filepath.Base(config.PodConfig)).Funcs(template.FuncMap(sprig.FuncMap())).ParseFiles(config.PodConfig)
	if err != nil {
		panic(err)
	}

	// Check offline mode, for Web UI testing
	var authInstance server.AuthManager
	var factoryInstance server.KubeFactory
	if config.OfflineUsername != "" {
		logger.WithFields(log.Fields{
			"username": config.OfflineUsername,
			"domain":   config.OfflineDomain,
			"password": config.OfflinePassword,
		}).Warn("Running in offline mode")
		authInstance = &mock.AuthManager{
			Username: config.OfflineUsername,
			Password: config.OfflinePassword,
			Service:  config.OfflineDomain,
			Token:    "test-offline-token",
		}
		factoryInstance = &mock.KubeFactory{
			PodInfo: kube.PodInfo{
				Name:  "offline_pod",
				Type:  "DELETED",
				Phase: "Unknown",
				Ready: false,
			},
		}
	} else {
		logger.WithFields(log.Fields{"keystone": config.KeystoneURL}).Info("Building auth manager")
		httpClient := &http.Client{
			Timeout: time.Duration(config.RequestTimeout) * time.Second,
		}
		// Use random signing key. Beware if we ever deploy more than one pod.
		var signingKey []byte
		if config.SigningKey != "" {
			logger.Info("Using configured signing key")
			signingKey = []byte(config.SigningKey)
		} else {
			logger.Info("Using random signing key")
			signingKey = make([]byte, 64)
			rand.Read(signingKey)
		}
		auth := auth.New(logger, httpClient, time.Duration(config.SessionLifetime)*time.Minute, config.KeystoneURL, jwt.SigningMethodHS256, jwt.Keyfunc(func(*jwt.Token) (interface{}, error) { return signingKey, nil }))
		defer auth.Cancel()

		// Build all paths for the app
		defaultPort := kube.ForwardPort{Scheme: "http", Port: config.PodPort}
		prefixPort := make(map[string]kube.ForwardPort)
		for path, port := range config.PrefixPort {
			prefixPort[path] = kube.ForwardPort{Scheme: "http", Port: port}
		}
		logger.WithFields(log.Fields{"port": defaultPort, "path": prefixPort}).Info("Building pod factory")
		factory := kube.NewFactory(logger, tmpl, time.Duration(config.PodLifetime)*time.Minute, defaultPort, prefixPort, config.ForwardedProto, server.SESSIONCOOKIE, config.Labels)
		defer factory.Cancel()

		logger.WithFields(log.Fields{"namespace": config.Namespace}).Info("Connecting to kubernetes API")
		api, err := kube.Loop(logger, config.Namespace, factory, config.Threads, config.Labels)
		if err != nil {
			panic(err)
		}
		defer api.Cancel()

		authInstance = authManager{Manager: auth}
		factoryInstance = kubeFactory{api: api, factory: factory}
	}

	logger.WithFields(log.Fields{"fowardedProto": config.ForwardedProto, "resources": config.StaticFolder}).Info("Building proxy server")
	proxy, err := server.New(logger, config.Redirect, config.ForwardedProto,
		config.Cors,
		localResources(logger, config.TemplateFolder, templates, "templates"),
		localResources(logger, config.StaticFolder, podstatic, "podstatic"),
		authInstance, factoryInstance)
	if err != nil {
		panic(err)
	}
	defer proxy.Cancel()

	// Start proxy and profiling servers
	var serverGroup sync.WaitGroup
	proxySrv := startServer(logger, &serverGroup, proxy, config.Port, config.RequestTimeout, config.IdleTimeout)
	pprofSrv := startServer(logger, &serverGroup, http.DefaultServeMux, config.ProfilePort, 0, config.IdleTimeout)

	// Wait for all tasks to finish
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	log.Warn("Exiting application on received signal")
	deadlineCtx, deadlineCancel := context.WithDeadline(context.Background(), time.Now().Add(time.Duration(config.GracefulShutdown)*time.Second))
	stopServer(deadlineCtx, &serverGroup, proxySrv)
	stopServer(deadlineCtx, &serverGroup, pprofSrv)
	serverGroup.Wait()
	deadlineCancel()
}

func startServer(logger *log.Logger, wg *sync.WaitGroup, mux http.Handler, port int, requestTimeout, idleTimeout int) *http.Server {
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      mux,
		ReadTimeout:  time.Duration(requestTimeout) * time.Second,
		WriteTimeout: time.Duration(requestTimeout) * time.Second,
		IdleTimeout:  time.Duration(idleTimeout) * time.Second,
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.WithField("port", port).Info("Starting service")
		if err := srv.ListenAndServe(); err != nil {
			if !errors.Is(err, http.ErrServerClosed) {
				panic(err)
			}
		}
	}()
	return srv
}

func stopServer(ctx context.Context, wg *sync.WaitGroup, srv *http.Server) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.Shutdown(ctx)
	}()
}

type authSession struct {
	manager *auth.Manager
	*auth.Session
}

type authManager struct {
	*auth.Manager
}

// Check implements server.AuthManager
func (a authManager) Check(token string) (auth.Credentials, server.AuthSession, error) {
	creds, session, err := a.Manager.Check(token)
	if err != nil {
		return creds, nil, err
	}
	if session == nil {
		return creds, nil, nil
	}
	return creds, authSession{manager: a.Manager, Session: session}, nil
}

// Check implements server.AuthManager
func (a authManager) Login(creds auth.Credentials, password string) (server.AuthSession, error) {
	s, err := a.Manager.Login(creds, password)
	if err != nil {
		return nil, err
	}
	return authSession{manager: a.Manager, Session: s}, nil
}

// Check implements server.SessionManager
func (s authSession) Logout() {
	s.manager.Logout(s.Session)
}

type kubeManager struct {
	api     *kube.API
	manager *kube.Manager
}

// Delete implements server.KubeManager
func (m kubeManager) Delete(ctx context.Context) error {
	return m.manager.Delete(ctx, m.api)
}

// Proxy implements server.KubeManager
func (m kubeManager) Proxy(ctx context.Context, create bool) (*kube.PodProxy, kube.PodInfo, error) {
	return m.manager.Proxy(ctx, m.api, create)
}

type kubeFactory struct {
	api     *kube.API
	factory *kube.Factory
}

// Find implements server.KubeFactory
func (f kubeFactory) Find(creds auth.Credentials) (server.KubeManager, error) {
	m, err := f.factory.Find(f.api, creds)
	if err != nil {
		return nil, err
	}
	return kubeManager{api: f.api, manager: m}, nil
}

// ServerVersion implements server.KubeFactory
func (f kubeFactory) ServerVersion() (fmt.Stringer, error) {
	return f.api.ServerVersion()
}
