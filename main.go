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
)

//go:embed resources/*
var resources embed.FS

// localResources checks if there is a local folder with resources
// Otherwise, it uses the embedded ones.
func localResources(logger *log.Logger, resourceDir string) fs.FS {
	loggerCtx := logger.WithField("resources", resourceDir)
	stat, err := os.Stat(resourceDir)
	if err != nil {
		if !os.IsNotExist(err) {
			panic(err)
		}
	} else {
		if stat.IsDir() {
			loggerCtx.Info("Using local resources")
			return os.DirFS(resourceDir)
		}
	}
	// Use embedded resources, but strip prefix to match
	// the local dir use case.
	loggerCtx.Info("Using embedded resources")
	sub, err := fs.Sub(&resources, "resources")
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

	logger.WithFields(log.Fields{"port": config.PodPort}).Info("Building pod factory")
	factory := NewFactory(logger, tmpl, time.Duration(config.PodLifetime)*time.Minute, "http", config.PodPort, config.ForwardedProto)
	defer factory.Cancel()

	logger.WithFields(log.Fields{"keystone": config.KeystoneURL}).Info("Connecting to kubernetes API")
	api, err := NewAPI(logger, config.Namespace)
	if err != nil {
		panic(err)
	}

	logger.Info("Building auth manager")
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
	auth := NewAuth(logger, time.Duration(config.SessionLifetime)*time.Minute, config.KeystoneURL, jwt.SigningMethodHS256, jwt.Keyfunc(func(*jwt.Token) (interface{}, error) { return signingKey, nil }))
	defer auth.Cancel()

	// TODO: Get resourceDir from environment variable
	logger.WithFields(log.Fields{"realm": config.Realm, "resources": config.ResourceFolder}).Info("Building proxy server")
	proxy, err := NewServer(logger, config.Realm, config.Redirect, localResources(logger, config.ResourceFolder), api, auth, factory)
	if err != nil {
		panic(err)
	}
	defer proxy.Cancel()

	var serverGroup sync.WaitGroup
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", config.Port),
		Handler: proxy,
	}
	serverGroup.Add(1)
	go func() {
		defer serverGroup.Done()
		logger.WithField("port", config.Port).Info("Starting service")
		if err := srv.ListenAndServe(); err != nil {
			if !errors.Is(err, http.ErrServerClosed) {
				panic(err)
			}
		}
	}()

	// Wait for all tasks to finish
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	log.Warn("Exiting application on received signal")
	deadlineCtx, deadlineCancel := context.WithDeadline(context.Background(), time.Now().Add(time.Duration(config.GracefulShutdown)*time.Second))
	srv.Shutdown(deadlineCtx)
	serverGroup.Wait()
	deadlineCancel()
}
