package main

import (
	"context"
	"fmt"
	"net/http/httputil"
	"net/url"
	"sync"

	log "github.com/sirupsen/logrus"
)

type PodManager struct {
	Logger     *log.Logger
	Descriptor *PodDescriptor
	Scheme     string
	Port       int
	// Information about last status change
	status PodPhase
	lastIP string
	proxy  *httputil.ReverseProxy
	// Pending operations
	pendingDelete bool
	// Watcher management
	cancel    context.CancelFunc
	waitGroup sync.WaitGroup
	// Protects everything except the waitGroup
	mutex sync.Mutex
}

// Returns a reversProxy instance pointing to the current pod IP address
func (m *PodManager) Proxy(ctx context.Context, api *KubeAPI, create bool) (*httputil.ReverseProxy, PodPhase, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if err := m.updateStatus(ctx, api, create); err != nil {
		return nil, "", err
	}
	return m.proxy, m.status, nil
}

// Destroy the pod
func (m *PodManager) Destroy(ctx context.Context, api *KubeAPI) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m.pendingDelete != false {
		return nil
	}
	m.pendingDelete = true
	m.mutex.Unlock()
	err := api.PodDelete(ctx, m.Descriptor.Name)
	m.mutex.Lock()
	if err != nil {
		m.pendingDelete = false
		return err
	}
	return nil
}

// Cancel the watcher, leave the pod behind.
// Waits for the watcher to finish.
func (m *PodManager) Cancel() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m.cancel != nil {
		m.cancel()
	}
}

// Wait for all resources to be free
func (m *PodManager) Wait() {
	m.Cancel()
	m.waitGroup.Wait()
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
	if m.cancel != nil {
		return nil
	}
	newCtx, cancelFunc := context.WithCancel(ctx)
	events, err := api.PodWatch(newCtx, m.Descriptor.Name)
	if err != nil {
		cancelFunc() // Unneeded, but just in case
		return err
	}
	m.cancel = cancelFunc
	// Keep updating events
	m.waitGroup.Add(1)
	go m.watch(events)
	return nil
}

func (m *PodManager) watch(events <-chan PodInfo) {
	defer m.waitGroup.Done()
	defer func() {
		m.mutex.Lock()
		defer m.mutex.Unlock()
		m.cancel()
		m.pendingDelete = false
		m.status = ""
		m.cancel = nil
	}()
	loggerCtx := m.Logger.WithField("name", m.Descriptor.Name)
	for info := range events {
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
		m.mutex.Unlock()
	}
}

func (m *PodManager) reverseProxy() *httputil.ReverseProxy {
	target := &url.URL{
		Scheme: m.Scheme,
		Host:   fmt.Sprintf("%s:%d", m.lastIP, m.Port),
	}
	tp := httputil.NewSingleHostReverseProxy(target)
	return tp
}
