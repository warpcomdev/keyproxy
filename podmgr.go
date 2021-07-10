package main

import (
	"context"
	"fmt"
	"net/http/httputil"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

// AtomicTimestamp stores an atomic unix timestamp
type AtomicTimestamp struct {
	timestamp int64
}

// Load the timestamp atomically
func (a *AtomicTimestamp) Load() int64 {
	return atomic.LoadInt64(&a.timestamp)
}

// Store the timestamp atomically
func (a *AtomicTimestamp) Store(v int64) {
	atomic.StoreInt64(&a.timestamp, v)
}

// PodManager handles the suscription to a pod's events
type PodManager struct {
	Logger     *log.Logger
	Descriptor *PodDescriptor
	// Scheme and port of the backend server to proxy to.
	// The IP address will be learnt from the kube cluster.
	Scheme string
	Port   int
	// Timestamp of last update to be used by PodFactory
	Timestamp AtomicTimestamp
	// Status, last known IP and resulting reverse proxy
	status PodPhase
	lastIP string
	proxy  *httputil.ReverseProxy
	// PendingDelete is set to true when pod is being destroyed
	pendingDelete bool
	// Mutex that protects everything
	mutex sync.Mutex
}

// Proxy instance to current pod's IP.
// Beware that the proxy might be nil if no IP, even when error == nil.
func (m *PodManager) Proxy(ctx context.Context, api *KubeAPI, create bool) (*httputil.ReverseProxy, PodPhase, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if err := m.updateStatus(ctx, api, create); err != nil {
		return nil, "", err
	}
	return m.proxy, m.status, nil
}

// Delete the pod
func (m *PodManager) Delete(ctx context.Context, api *KubeAPI) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m.pendingDelete != false {
		return nil
	}
	m.pendingDelete = true
	err := api.PodDelete(ctx, m.Descriptor.Name)
	if err != nil {
		m.pendingDelete = false
		return err
	}
	return nil
}

// updateStatus must be called with the lock held
func (m *PodManager) updateStatus(ctx context.Context, api *KubeAPI, create bool) error {
	// If we don't know the container status, ask for it
	if m.status == "" {
		info, err := api.PodStatus(ctx, m.Descriptor.Name)
		if err != nil {
			return err
		}
		m.status = info.PodPhase
		m.lastIP = info.Address
		// In case the pod is running, build a reverse proxy
		if info.PodPhase == PodRunning && info.Address != "" {
			m.proxy = m.reverseProxy()
		}
	}
	if m.status == PodMissing && create {
		err := api.PodCreate(ctx, m.Descriptor)
		if err != nil {
			return err
		}
		if m.status == "" || m.status == PodMissing {
			m.status = PodPending
		}
	}
	return nil
}

// Watch the pod status to keep updating the proxy when IP address changes.
// If the watch is closed or the ctx or lifetime expire, it calls the cleanup func.
func (m *PodManager) Watch(ctx context.Context, api *KubeAPI, lifetime time.Duration, cleanup func()) error {
	cancelCtx, cancelFunc := context.WithCancel(ctx)
	watch, err := api.PodWatch(cancelCtx, m.Descriptor.Name)
	if err != nil {
		cancelFunc() // Just in case
		return err
	}
	loggerCtx := m.Logger.WithField("name", m.Descriptor.Name)
	go func() {
		defer cleanup()
		defer func() {
			// Exhaust watcher to make sure kubernetes suscription is cleared
			cancelFunc()
			for range watch {
			}
		}()
		timer := time.NewTimer(lifetime + time.Second)
		// Don't defer timer.stop(), because defer is evaluated in this
		// point, but timer can be changed later on.
		// Instead, stop timer at every exit point.
		// defer timer.Stop()
		for {
			select {
			case <-timer.C:
				now := time.Now().Unix()
				timestamp := m.Timestamp.Load()
				remaining := timestamp + int64(lifetime/time.Second) - now
				if remaining <= 0 {
					loggerCtx.Info("Watch thread expired")
					return
				}
				timer = time.NewTimer(time.Duration(remaining+1) * time.Second)
			case <-ctx.Done():
				loggerCtx.Info("Watch thread context cancelled")
				timer.Stop()
				return
			case info, ok := <-watch:
				if !ok {
					loggerCtx.Info("Watch thread finished")
					timer.Stop()
					return
				}
				loggerCtx.WithField("event", info).Debug("Received event")
				m.mutex.Lock()
				m.status = info.PodPhase
				if m.lastIP != info.Address {
					if info.Address == "" {
						loggerCtx.Info("Pod lost its IP address")
						m.proxy = nil
					} else {
						m.proxy = m.reverseProxy()
					}
					m.lastIP = info.Address
				}
				// TODO: clear pendingDelete only when received destroy event.
				if m.pendingDelete {
					m.status = PodMissing
					m.pendingDelete = false
				}
				m.mutex.Unlock()
			}
		}
	}()
	return nil
}

// reverseProxy must be called with the mutex held
func (m *PodManager) reverseProxy() *httputil.ReverseProxy {
	target := &url.URL{
		Scheme: m.Scheme,
		Host:   fmt.Sprintf("%s:%d", m.lastIP, m.Port),
	}
	tp := httputil.NewSingleHostReverseProxy(target)
	return tp
}
