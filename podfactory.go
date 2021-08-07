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
	managersByKey  map[string]*PodManager
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
		managers:      make(map[Credentials]*PodManager),
		managersByKey: make(map[string]*PodManager),
	}
	// Keep track of time
	factory.Tick(time.Second)
	return factory
}

// Find manager for the given credentials.
func (f *PodFactory) Find(api *KubeAPI, creds Credentials) (*PodManager, error) {
	logger := f.Logger.WithField("creds", creds)
	f.Mutex.Lock()
	defer f.Mutex.Unlock()
	mgr, ok := f.managers[creds]
	if !ok {
		if f.cancelFunc == nil {
			return nil, ErrorFactoryCancelled
		}
		logger.Info("Creating new manager")
		var err error // Beware! we can't do ":=" below, otherwise it would shadow mgr above
		mgr, err = f.newManager(api, creds)
		if err != nil {
			return nil, err
		}
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

// newManager creates a manager and starts the pod watch.
// This must be called with the mutex held.
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
	f.managers[creds] = manager
	f.managersByKey[pod.GetName()] = manager
	f.Group.Add(1)
	go f.watch(api, creds, manager)
	return manager, nil
}

// Watch podmanager lifetime, calls f.Group.Done() when done
func (f *PodFactory) watch(api *KubeAPI, creds Credentials, manager *PodManager) {
	defer f.Group.Done()
	deadline := time.NewTimer(f.Lifetime + time.Second)
	logger := f.Logger.WithFields(log.Fields{"creds": creds, "name": manager.Descriptor.GetName()})
	for {
		select {
		case <-deadline.C:
			remaining := manager.Timestamp.Remaining(f.Lifetime)
			if remaining <= 0 {
				logger.Info("Watch thread expired, deleting pod")
				ctx, cancelFunc := context.WithDeadline(context.Background(), time.Now().Add(10*time.Second))
				err := manager.Delete(ctx, api)
				cancelFunc()
				if err == nil {
					// Also remove the pod from the maps
					f.Mutex.Lock()
					delete(f.managers, creds)
					delete(f.managersByKey, manager.Descriptor.GetName())
					f.Mutex.Unlock()
					return
				}
				logger.WithError(err).Error("Failed to remove pod")
				remaining = f.Lifetime / 2
			}
			deadline = time.NewTimer(remaining + time.Second)
		case <-f.cancelCtx.Done():
			deadline.Stop()
			return
		}
	}
}

// Update manager status on pod info received
func (f *PodFactory) Update(info PodInfo) error {
	f.Mutex.Lock()
	manager, ok := f.managersByKey[info.Name]
	f.Mutex.Unlock()
	if ok {
		manager.Update(info)
	}
	return nil
}

// Get implements httputil.BufferPool
func (f *PodFactory) Get() []byte {
	return f.BufferPool.Get().([]byte)
}

// Put implements httputil.BufferPool
func (f *PodFactory) Put(buf []byte) {
	f.BufferPool.Put(buf)
}
