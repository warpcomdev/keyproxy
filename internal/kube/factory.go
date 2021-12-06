package kube

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"text/template"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/warpcomdev/keyproxy/internal/auth"
	"github.com/warpcomdev/keyproxy/internal/clock"
)

const (
	BUFFER_POOL_SIZE = 32 * 1024 // Same as default pool size for httputil.ReverseProxy
)

var ErrorFactoryCancelled = errors.New("PodFactory is being cancelled")

type Factory struct {
	// Keeper must be at the top of the struct for atomic calls
	clock.Keeper
	Logger   *log.Logger
	Template *template.Template
	Lifetime time.Duration
	ForwardPort
	PrefixPort     map[string]ForwardPort // Additional ports for custom path prefixes
	ForwardedProto string
	BufferPool     sync.Pool
	SessionCookie  string
	managers       map[auth.Credentials]*Manager
	managersByKey  map[string]*Manager
	Labels         map[string]string
}

// NewFactory creates a Factory for Managers
func NewFactory(logger *log.Logger, tmpl *template.Template, lifetime time.Duration, defaultPort ForwardPort, prefixPort map[string]ForwardPort, forwardedProto string, sessionCookie string, labels map[string]string) *Factory {
	factory := &Factory{
		Logger:         logger,
		Template:       tmpl,
		Lifetime:       lifetime,
		ForwardPort:    defaultPort,
		PrefixPort:     prefixPort,
		ForwardedProto: forwardedProto,
		SessionCookie:  sessionCookie,
		BufferPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, BUFFER_POOL_SIZE)
			},
		},
		managers:      make(map[auth.Credentials]*Manager),
		managersByKey: make(map[string]*Manager),
		Labels:        labels,
	}
	// Keep track of time
	factory.Tick(time.Second)
	return factory
}

// Find manager for the given credentials.
func (f *Factory) Find(api *API, creds auth.Credentials) (*Manager, error) {
	logger := f.Logger.WithField("creds", creds)
	f.Mutex.Lock()
	defer f.Mutex.Unlock()
	mgr, ok := f.managers[creds]
	if !ok {
		if f.CancelFunc == nil {
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
func (f *Factory) newManager(api *API, creds auth.Credentials) (*Manager, error) {
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
	// Add keyproxy label for better filtering
	labels := pod.ObjectMeta.Labels
	if labels == nil {
		labels = make(map[string]string)
	}
	for k, v := range f.Labels {
		labels[k] = v
	}
	pod.ObjectMeta.Labels = labels
	manager := &Manager{
		Logger:         f.Logger,
		Descriptor:     pod,
		ForwardPort:    f.ForwardPort,
		PrefixPort:     f.PrefixPort,
		ForwardedProto: f.ForwardedProto,
		Pool:           f,
		SessionCookie:  f.SessionCookie,
	}
	f.managers[creds] = manager
	f.managersByKey[pod.GetName()] = manager
	f.Group.Add(1)
	go f.watch(api, creds, manager)
	return manager, nil
}

// Watch podmanager lifetime, calls f.Group.Done() when done
func (f *Factory) watch(api *API, creds auth.Credentials, manager *Manager) {
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
		case <-f.CancelCtx.Done():
			deadline.Stop()
			return
		}
	}
}

// Update manager status on pod info received
func (f *Factory) Update(info PodInfo) error {
	f.Mutex.Lock()
	manager, ok := f.managersByKey[info.Name]
	f.Mutex.Unlock()
	if ok {
		manager.Update(info)
	}
	return nil
}

// Get implements httputil.BufferPool
func (f *Factory) Get() []byte {
	return f.BufferPool.Get().([]byte)
}

// Put implements httputil.BufferPool
func (f *Factory) Put(buf []byte) {
	f.BufferPool.Put(buf)
}
