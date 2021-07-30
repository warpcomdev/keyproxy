package main

import (
	"bytes"
	"errors"
	"sync"
	"text/template"
	"time"

	log "github.com/sirupsen/logrus"
)

const BUFFER_POOL_SIZE = 32 * 1024 // Same as default pool size for httputil.ReverseProxy

var ErrorFactoryCancelled = errors.New("PodFactory is being cancelled")

type PodFactory struct {
	// TimeKeeper must be at the top of the struct for atomic calls
	TimeKeeper
	Logger         *log.Logger
	Template       *template.Template
	Lifetime       time.Duration
	Scheme         string
	Port           int
	ForwardedProto string
	BufferPool     sync.Pool
	managers       map[Credentials]*PodManager
}

// NewFactory creates a Factory for PodManagers
func NewFactory(logger *log.Logger, tmpl *template.Template, lifetime time.Duration, scheme string, port int, forwardedProto string) *PodFactory {
	factory := &PodFactory{
		Logger:         logger,
		Template:       tmpl,
		Lifetime:       lifetime,
		Scheme:         scheme,
		Port:           port,
		ForwardedProto: forwardedProto,
		BufferPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, BUFFER_POOL_SIZE)
			},
		},
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

// PodParameters are the parameters for the pod template
type PodParameters struct {
	Username  string
	Service   string
	Namespace string
}

// newManager creates a manager and starts the pod watch
func (f *PodFactory) newManager(api *KubeAPI, creds Credentials) (*PodManager, error) {
	buffer := &bytes.Buffer{}
	params := PodParameters{
		Username:  creds.Username,
		Service:   creds.Service,
		Namespace: api.Namespace,
	}
	if err := f.Template.Execute(buffer, params); err != nil {
		return nil, err
	}
	pod, err := api.Decode(buffer.String())
	if err != nil {
		return nil, err
	}
	manager := &PodManager{
		Logger:         f.Logger,
		Descriptor:     pod,
		Scheme:         f.Scheme,
		Port:           f.Port,
		ForwardedProto: f.ForwardedProto,
		Pool:           f,
	}
	f.Group.Add(1)
	err = manager.Watch(f.cancelCtx, api, f.Lifetime, func() {
		defer f.Group.Done()
		f.Mutex.Lock()
		delete(f.managers, creds)
		f.Mutex.Unlock()
	})
	if err != nil {
		f.Group.Done() // since cleanup function above won't be called
		return nil, err
	}
	return manager, nil
}

// Get implements httputil.BufferPool
func (f *PodFactory) Get() []byte {
	return f.BufferPool.Get().([]byte)
}

// Put implements httputil.BufferPool
func (f *PodFactory) Put(buf []byte) {
	f.BufferPool.Put(buf)
}
