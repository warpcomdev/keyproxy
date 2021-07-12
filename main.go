package main

import (
	"crypto/rand"
	"embed"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"text/template"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/masterminds/sprig"
	log "github.com/sirupsen/logrus"
)

const (
	PODCONFIG = "configs/pod.yaml"
	REALM     = "KeyProxy Auth"
)

// POD_LIFETIME: Destroy pod after this long without activity
const POD_LIFETIME = 2 * time.Hour

// SESSION_LIFETIME: Destroy session after this long without activity
const SESSION_LIFETIME = 1 * time.Hour

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

	logger.WithFields(log.Fields{"podconfig": PODCONFIG}).Info("Reading pod template")
	tmpl, err := template.New(filepath.Base(PODCONFIG)).Funcs(template.FuncMap(sprig.FuncMap())).ParseFiles(PODCONFIG)
	if err != nil {
		panic(err)
	}

	logger.WithFields(log.Fields{"port": 8080}).Info("Building pod factory")
	factory := NewFactory(logger, tmpl, POD_LIFETIME, "http", 8080)
	defer factory.Cancel()

	logger.Info("Connecting to kubernetes API")
	// TODO: Get namespace from config
	namespace := ""
	api, err := NewAPI(logger, namespace)
	if err != nil {
		panic(err)
	}

	logger.Info("Building auth manager")
	// Use random signing key. Beware if we ever deploy more than one pod.
	signingKey := make([]byte, 64)
	rand.Read(signingKey)
	auth := NewAuth(logger, SESSION_LIFETIME, jwt.SigningMethodHS256, jwt.Keyfunc(func(*jwt.Token) (interface{}, error) { return signingKey, nil }))
	defer auth.Cancel()

	// TODO: Get resourceDir from environment variable
	resourceDir := "resources"
	logger.WithFields(log.Fields{"realm": REALM, "resources": resourceDir}).Info("Building proxy server")
	proxy, err := NewServer(logger, REALM, localResources(logger, resourceDir), api, auth, factory)
	if err != nil {
		panic(err)
	}
	defer proxy.Cancel()

	logger.WithField("port", 8080).Info("Starting service")
	srv := &http.Server{
		Addr:    ":8080",
		Handler: proxy,
	}
	if err := srv.ListenAndServe(); err != nil {
		panic(err)
	}
}
