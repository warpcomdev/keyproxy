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
	KILLPATH     = "/kill"
	RESOURCEPATH = "/resources"
	PODCONFIG    = "/configs/pod.yaml"
)

func main() {

	logger := log.New()
	logger.Level = log.DebugLevel
	logger.Out = os.Stdout

	logger.WithFields(log.Fields{"podconfig": PODCONFIG, "port": 9390}).Info("Building pod factory")
	tmpl, err := template.ParseFiles(PODCONFIG)
	if err != nil {
		panic(err)
	}
	tmpl.Funcs(template.FuncMap(sprig.FuncMap()))
	factory := &PodFactory{
		Logger:   logger,
		Template: tmpl,
		Port:     9390,
	}

	logger.Info("Connection to kubernetes API")
	api, err := NewAPI(logger, filepath.Join(homedir.HomeDir(), ".kube", "config"), "")
	if err != nil {
		panic(err)
	}

	logger.WithField("port", 8080).Info("Building proxy server")
	srv := &http.Server{
		Addr: ":8080",
		Handler: &rootHandler{
			Factory:   factory,
			Api:       api,
			Resources: &resources,
			Logger:    logger,
			Realm:     "Keyproxy Auth",
		},
	}
	if err := srv.ListenAndServe(); err != nil {
		panic(err)
	}
}
