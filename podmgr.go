package main

import (
	"context"
	"fmt"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// PodManager handles the suscription to a pod's events
type PodManager struct {
	// Timestamp of last update to be used by PodFactory.
	// Must be at the top of the struct for atomic ops to work.
	Timestamp  AtomicTimestamp
	Logger     *log.Logger
	Descriptor *PodDescriptor
	// Scheme and port of the backend server to proxy to.
	// The IP address will be learnt from the kube cluster.
	Scheme string
	Port   int
	// latest status detected and resulting reverse proxy
	latest PodInfo
	proxy  *httputil.ReverseProxy
	// PendingDelete is set to true when pod is being destroyed
	pendingDelete bool
	// Mutex that protects everything
	mutex sync.Mutex
}

// Proxy returns a httputil.ReverseProxy instance to current pod's IP.
// If create == true, the pod will be scheduled for creation if not existing.
// Beware that the proxy might be nil if no IP, even when error == nil.
func (m *PodManager) Proxy(ctx context.Context, api *KubeAPI, create bool) (*httputil.ReverseProxy, PodInfo, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if err := m.updateStatus(ctx, api, create); err != nil {
		return nil, PodInfo{}, err
	}
	return m.proxy, m.latest, nil
}

// Delete the pod
func (m *PodManager) Delete(ctx context.Context, api *KubeAPI) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m.pendingDelete != false {
		return nil
	}
	m.pendingDelete = true
	err := api.DeletePod(ctx, m.Descriptor.Name)
	if err != nil {
		m.pendingDelete = false
		return err
	}
	return nil
}

// updateStatus must be called with the lock held
func (m *PodManager) updateStatus(ctx context.Context, api *KubeAPI, create bool) error {
	// If we don't know the container status, ask for it
	if m.latest.Phase == "" {
		info, err := api.PodStatus(ctx, m.Descriptor.Name)
		if err != nil {
			return err
		}
		m.latest = info
		// In case the pod is running, build a reverse proxy
		if info.Type != Deleted && info.Phase == PodRunning && info.Address != "" {
			m.proxy = m.reverseProxy(info.Address)
		}
	}
	if m.latest.Type == Deleted && create {
		err := api.CreatePod(ctx, m.Descriptor)
		if err != nil {
			return err
		}
		// Change event so that we won't create it again
		m.latest.Type = Modified
	}
	return nil
}

// Watch the pod status to keep updating the proxy when IP address changes.
// If the watch is closed or the ctx or lifetime expire, it calls the cleanup func.
func (m *PodManager) Watch(ctx context.Context, api *KubeAPI, lifetime time.Duration, cleanup func()) error {
	cancelCtx, cancelFunc := context.WithCancel(ctx)
	watch, err := api.WatchPod(cancelCtx, m.Descriptor.Name)
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
				now := UnixTimestamp(time.Now().Unix())
				timestamp := m.Timestamp.Load()
				remaining := timestamp + UnixTimestamp(lifetime/time.Second) - now
				if remaining <= 0 {
					loggerCtx.Info("Watch thread expired, deleting pod")
					m.Delete(ctx, api)
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
				loggerEvent := loggerCtx.WithField("event", info)
				m.mutex.Lock()
				switch {
				case info.Type == Deleted || info.Phase != PodRunning || info.Address == "":
					loggerEvent.Info("Pod not ready for proxy")
					m.proxy = nil
				case m.latest.Address != info.Address:
					loggerEvent.Info("Updating proxy address")
					m.proxy = m.reverseProxy(info.Address)
				}
				m.latest = info
				if info.Type == Deleted {
					m.pendingDelete = false
				}
				m.mutex.Unlock()
			}
		}
	}()
	return nil
}

// reverseProxy builds the reverse proxy instance.
func (m *PodManager) reverseProxy(address string) *httputil.ReverseProxy {
	target := &url.URL{
		Scheme: m.Scheme,
		Host:   fmt.Sprintf("%s:%d", address, m.Port),
	}
	tp := httputil.NewSingleHostReverseProxy(target)
	return tp
}
