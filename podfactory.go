package main

import (
	"bytes"
	"errors"
	"text/template"
	"time"

	log "github.com/sirupsen/logrus"
)

// POD_LIFETIME: Destroy pod after this long without activity
const (
	POD_LIFETIME = 2 * time.Hour
)

var ErrorFactoryCancelled = errors.New("PodFactory is being cancelled")

type PodFactory struct {
	// TimeKeeper must be at the top of the struct for atomic calls
	TimeKeeper
	Logger   *log.Logger
	Template *template.Template
	Scheme   string
	Port     int
	managers map[Credentials]*PodManager
}

// NewFactory creates a Factory for PodManagers
func NewFactory(logger *log.Logger, tmpl *template.Template, scheme string, port int) *PodFactory {
	factory := &PodFactory{
		Logger:   logger,
		Template: tmpl,
		Scheme:   scheme,
		Port:     port,
		managers: make(map[Credentials]*PodManager),
	}
	// Keep track of time
	factory.Tick(time.Second)
	return factory
}

// Find manager for the given credentials.
func (f *PodFactory) Find(api *KubeAPI, creds Credentials) (*PodManager, error) {
	ctxLogger := f.Logger.WithField("creds", creds)
	f.Mutex.Lock()
	defer f.Mutex.Unlock()
	mgr, ok := f.managers[creds]
	if !ok {
		if f.cancelFunc == nil {
			return nil, ErrorFactoryCancelled
		}
		ctxLogger.Info("Creating new manager")
		var err error // Beware! we can't do ":=" below, otherwise it would shadow mgr above
		mgr, err = f.newManager(api, creds)
		if err != nil {
			return nil, err
		}
		f.managers[creds] = mgr
	}
	mgr.Timestamp.Store(f.Clock())
	return mgr, nil
}

// newManager creates a manager and starts the pod watch
func (f *PodFactory) newManager(api *KubeAPI, creds Credentials) (*PodManager, error) {
	buffer := &bytes.Buffer{}
	if err := f.Template.Execute(buffer, creds); err != nil {
		return nil, err
	}
	pod, err := api.Decode(buffer.String())
	if err != nil {
		return nil, err
	}
	manager := &PodManager{
		Logger:     f.Logger,
		Descriptor: pod,
		Scheme:     f.Scheme,
		Port:       f.Port,
	}
	f.Group.Add(1)
	err = manager.Watch(f.cancelCtx, api, POD_LIFETIME, func() {
		defer f.Group.Done()
		f.Mutex.Lock()
		delete(f.managers, creds)
		f.Mutex.Unlock()
	})
	if err != nil {
		f.Group.Done() // since cleanup functon above won't be called
		return nil, err
	}
	return manager, nil
}
