package main

import (
	"context"
	"errors"
	"hash/fnv"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// Time before auth expiration when auth will be retried
	GRACE_PERIOD_SECONDS = 10 * 60
	// Number of bits of te hash used for anti-bruteforce ratelimit
	LOGIN_HASH_BITS = 12
)

var ErrorTooManyAttempts = errors.New("Too many concurrent auth attempts")
var ErrorAuthCancelled = errors.New("AuthManager is being cancelled")

// Credentials for authentication
type Credentials struct {
	Service  string
	Username string
}

// AuthManager handles credential resolution, ratelimit and cache
type AuthManager struct {
	// AtomicTimestamp must be at the top of the struct
	timestamp AtomicTimestamp
	Logger    *log.Logger
	// cache TODO: expire cached credentials. Is it worth it? there won't be so many.
	cache      map[uint64]UnixTimestamp
	loginHash  []UnixTimestamp
	mutex      sync.Mutex
	cancelCtx  context.Context
	cancelFunc context.CancelFunc
	waitGroup  sync.WaitGroup
}

// NewAuth creates new Auth Manager
func NewAuth(logger *log.Logger) *AuthManager {
	cancelCtx, cancelFunc := context.WithCancel(context.Background())
	manager := &AuthManager{
		Logger:     logger,
		cache:      make(map[uint64]UnixTimestamp),
		loginHash:  make([]UnixTimestamp, 0, 1<<LOGIN_HASH_BITS),
		cancelCtx:  cancelCtx,
		cancelFunc: cancelFunc,
	}
	manager.waitGroup.Add(1)
	go func() {
		defer manager.waitGroup.Done()
		manager.timestamp.timeKeeper(cancelCtx, time.Second)
	}()
	return manager
}

// hash would not be safe for password storage, but
// it won't be stored anywhere, nor is it associated with
// an username and service anywhere.
func hash(cred Credentials, password string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(cred.Service))
	h.Write([]byte(cred.Username))
	h.Write([]byte(password))
	return h.Sum64()
}

// Check the credential cache for a match that has not expired yet.
func (m *AuthManager) Check(cred Credentials, pass string) (bool, error) {
	credHash := hash(cred, pass)
	timestamp := m.timestamp.Load()
	m.mutex.Lock()
	defer m.mutex.Unlock()
	deadline, ok := m.cache[credHash]
	if ok && deadline <= timestamp {
		delete(m.cache, credHash)
		ok = false
	}
	if !ok {
		if m.cancelFunc == nil {
			return false, ErrorAuthCancelled
		}
		var err error
		deadline, err = m.refresh(cred, pass, credHash, timestamp)
		if err != nil {
			return false, err
		}
		if deadline <= timestamp {
			return false, nil
		}
		m.cache[credHash] = deadline
	}
	if deadline <= timestamp {
		delete(m.cache, credHash)
		return false, nil
	}
	if deadline > timestamp+GRACE_PERIOD_SECONDS {
		return true, nil
	}
	// If deadline is close, we try to refresh the auth.
	// Avoid several concurrent attempts to refresh the
	// auth by optimistically increase the deadline by the
	// grace period.
	tempDeadline := deadline + GRACE_PERIOD_SECONDS
	m.cache[credHash] = tempDeadline
	newDeadline, err := m.refresh(cred, pass, credHash, timestamp)
	if err != nil {
		// If error, restore the previous deadline
		m.cache[credHash] = deadline
		return true, nil
	}
	if newDeadline > timestamp {
		m.cache[credHash] = newDeadline
		return true, nil
	}
	delete(m.cache, credHash)
	return false, err
}

// refresh must be called with the mutex held
func (m *AuthManager) refresh(cred Credentials, pass string, hash uint64, timestamp UnixTimestamp) (UnixTimestamp, error) {
	// Must rate-limit per slot. A slot => 12 bits of the hash.
	bitMask := hash & ((1 << LOGIN_HASH_BITS) - 1)
	busy := m.loginHash[bitMask] > timestamp
	if busy {
		return 0, ErrorTooManyAttempts
	}
	m.loginHash[bitMask] = timestamp
	m.mutex.Unlock()
	defer m.mutex.Lock()
	deadline, err := m.login(cred, pass)
	// Make sure there is room enough for token renewal
	if deadline > 0 && deadline < timestamp+2*GRACE_PERIOD_SECONDS {
		deadline = timestamp + 2*GRACE_PERIOD_SECONDS
	}
	return deadline, err
}

// login must be called with the mutex NOT held
func (m *AuthManager) login(cred Credentials, pass string) (UnixTimestamp, error) {
	return UnixTimestamp(time.Now().Unix() + 3600), nil
}

func (m *AuthManager) Cancel() {
	m.mutex.Lock()
	cancelFunc := m.cancelFunc
	if cancelFunc == nil {
		m.mutex.Unlock()
		return
	}
	m.cancelFunc = nil
	m.mutex.Unlock()
	cancelFunc()
	m.waitGroup.Wait()
}
