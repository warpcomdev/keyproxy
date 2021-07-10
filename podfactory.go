package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"text/template"
	"time"

	log "github.com/sirupsen/logrus"
)

type Credentials struct {
	Service  string
	Username string
}

// LIFETIME: Destroy pod after this long without activity
const LIFETIME = 2 * time.Hour

// Hash() is not thread safe, beware...
func (c *Credentials) Hash(password string) string {
	h := sha256.New()
	h.Write([]byte(c.Service))
	h.Write([]byte(c.Username))
	h.Write([]byte(password))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

type PodFactory struct {
	Logger    *log.Logger
	Template  *template.Template
	Scheme    string
	Port      int
	managers  map[Credentials]*PodManager
	mutex     sync.Mutex
	waitGroup sync.WaitGroup
	// timestamp and done are used by the timekeeping thread
	timestamp AtomicTimestamp
	// cancelCtx used for management of channel lifetimes
	cancelCtx  context.Context
	cancelFunc context.CancelFunc
}

// Find manager for the given credentials.
func (f *PodFactory) Find(api *KubeAPI, creds Credentials) (*PodManager, error) {
	ctxLogger := f.Logger.WithField("creds", creds)
	f.mutex.Lock()
	defer f.mutex.Unlock()
	mgr, ok := f.managers[creds]
	if !ok {
		if f.cancelFunc == nil {
			return nil, errors.New("PodFactory is being cancelled")
		}
		ctxLogger.Info("Creating new manager")
		mgr, err := f.newManager(api, creds)
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
	err = manager.Watch(f.cancelCtx, api, LIFETIME, func() {
		defer f.waitGroup.Done()
		f.mutex.Lock()
		delete(f.managers, creds)
		f.mutex.Unlock()
	})
	if err != nil {
		return nil, err
	}
	f.waitGroup.Add(1)
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
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-cancelCtx.Done():
				return
			case now := <-ticker.C:
				factory.timestamp.Store(now.Unix())
			}
		}
	}()
	return factory
}
