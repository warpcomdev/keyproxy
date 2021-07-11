package main

import (
	"bytes"
	"context"
	"errors"
	"sync"
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
	// AtomicTimestamp must be at the top of the struct for atomic calls
	timestamp AtomicTimestamp
	Logger    *log.Logger
	Template  *template.Template
	Scheme    string
	Port      int
	managers  map[Credentials]*PodManager
	mutex     sync.Mutex
	waitGroup sync.WaitGroup
	// cancelCtx used for management of channel lifetimes
	cancelCtx  context.Context
	cancelFunc context.CancelFunc
}

// NewFactory creates a Factory for PodManagers
func NewFactory(logger *log.Logger, tmpl *template.Template, scheme string, port int) *PodFactory {
	cancelCtx, cancelFunc := context.WithCancel(context.Background())
	factory := &PodFactory{
		Logger:     logger,
		Template:   tmpl,
		Scheme:     scheme,
		Port:       port,
		managers:   make(map[Credentials]*PodManager),
		cancelCtx:  cancelCtx,
		cancelFunc: cancelFunc,
	}
	// Keep track of time
	factory.waitGroup.Add(1)
	go func() {
		defer factory.waitGroup.Done()
		factory.timestamp.timeKeeper(cancelCtx, time.Second)
	}()
	return factory
}

// Find manager for the given credentials.
func (f *PodFactory) Find(api *KubeAPI, creds Credentials) (*PodManager, error) {
	ctxLogger := f.Logger.WithField("creds", creds)
	f.mutex.Lock()
	defer f.mutex.Unlock()
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
	mgr.Timestamp.Store(f.timestamp.Load())
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
	f.waitGroup.Add(1)
	err = manager.Watch(f.cancelCtx, api, POD_LIFETIME, func() {
		defer f.waitGroup.Done()
		f.mutex.Lock()
		delete(f.managers, creds)
		f.mutex.Unlock()
	})
	if err != nil {
		f.waitGroup.Done() // since cleanup functon above won't be called
		return nil, err
	}
	return manager, nil
}

// Cancel all the watches and wait for termination
func (f *PodFactory) Cancel() {
	var cancelFunc context.CancelFunc
	f.mutex.Lock()
	if f.cancelFunc == nil {
		f.mutex.Unlock()
		return
	}
	cancelFunc = f.cancelFunc
	f.cancelFunc = nil
	f.mutex.Unlock()
	cancelFunc()
	f.waitGroup.Wait()
}
