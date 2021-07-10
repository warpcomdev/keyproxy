package main

import (
	"net/http"
	"os"
	"path/filepath"
	"text/template"

	"github.com/masterminds/sprig"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/util/homedir"
)

const (
	PODCONFIG = "configs/pod.yaml"
	REALM     = "KeyProxy Auth"
)

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
	factory := NewFactory(logger, tmpl, "http", 8080)
	defer factory.Cancel()

	logger.Info("Connecting to kubernetes API")
	api, err := NewAPI(logger, filepath.Join(homedir.HomeDir(), ".kube", "config"), "")
	if err != nil {
		panic(err)
	}

	logger.WithField("realm", REALM).Info("Building proxy server")
	proxy, err := NewServer(logger, REALM, &resources, api, factory)
	if err != nil {
		panic(err)
	}

	logger.WithField("port", 8080).Info("Starting service")
	srv := &http.Server{
		Addr:    ":8080",
		Handler: proxy,
	}
	if err := srv.ListenAndServe(); err != nil {
		panic(err)
	}
}
