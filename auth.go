package main

import (
	"context"
	"errors"
	"hash/fnv"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
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

// hash as a double-check that a session is valid.
func (cred Credentials) Hash(password string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(cred.Service))
	h.Write([]byte(cred.Username))
	h.Write([]byte(password))
	return h.Sum32()
}

// AuthSession keeps authentication session status
type AuthSession struct {
	AccessTime AtomicTimestamp
	Token      string
	Expiration time.Time
	Hash       uint32
	Logout     bool
}

// AuthManager handles credential resolution, ratelimit and cache
type AuthManager struct {
	// TimeKeeper must be at the top of the struct
	TimeKeeper
	Logger   *log.Logger
	Lifetime time.Duration
	// cache TODO: expire cached credentials. Is it worth it? there won't be so many.
	cache     map[Credentials]*AuthSession
	loginHash []UnixTimestamp
}

// NewAuth creates new Auth Manager
func NewAuth(logger *log.Logger, lifetime time.Duration) *AuthManager {
	manager := &AuthManager{
		Logger:    logger,
		cache:     make(map[Credentials]*AuthSession),
		loginHash: make([]UnixTimestamp, 0, 1<<LOGIN_HASH_BITS),
		Lifetime:  lifetime,
	}
	manager.Tick(time.Second)
	return manager
}

// Check the credential cache for a match that has not expired yet.
func (m *AuthManager) Check(cred Credentials, hash uint32) (*AuthSession, error) {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()
	session, ok := m.cache[cred]
	if !ok {
		return nil, nil
	}
	if hash != session.Hash || session.Logout {
		return nil, nil
	}
	session.AccessTime.Store(m.Clock())
	return session, nil
}

// Login with credentials and password.
// If hash is provided and matches an existing hash,
// password is assumed to be ok and not checked.
func (m *AuthManager) Login(cred Credentials, password string, hash uint32) (*AuthSession, error) {

	// Check if the credentials match an existing hash
	timestamp := m.Clock()
	m.Mutex.Lock()
	defer m.Mutex.Unlock()
	session, existing := m.cache[cred]
	if existing && session.Hash == hash && !session.Logout {
		return session, nil
	}

	// Rate-limit based on buckets
	credHash := cred.Hash(password)
	bitMask := credHash & ((1 << LOGIN_HASH_BITS) - 1)
	if m.loginHash[bitMask] >= timestamp {
		return nil, ErrorTooManyAttempts
	}
	m.loginHash[bitMask] = timestamp

	// Fill session data. This is a race, since I release the lock.
	m.Mutex.Unlock()
	token, exp, err := m.restLogin(cred, password)
	m.Mutex.Lock()
	if err != nil || token == "" {
		return nil, err
	}

	// Update session.
	// If some other thread has updated the session while I was
	// performing the request, it is the winner... use their session.
	session, existing = m.cache[cred]
	if !existing {
		session = &AuthSession{
			Hash:   credHash,
			Logout: true,
		}
	}
	session.AccessTime.Store(m.Clock())
	session.Token = token
	session.Expiration = exp
	session.Logout = false
	// If I'm the winner, I get to run the atcher and store my session
	if !existing {
		m.cache[cred] = session
		m.Group.Add(1)
		go func() {
			m.Group.Done()
			m.Watch(m.cancelCtx, cred, session)
		}()
	}
	return session, nil
}

func (m *AuthManager) Watch(ctx context.Context, cred Credentials, session *AuthSession) {
	// When the watch is done, remove the session from cache
	defer func() {
		m.Mutex.Lock()
		delete(m.cache, cred)
		m.Mutex.Unlock()
	}()
	loggerCtx := m.Logger.WithField("cred", cred)
	timer := time.NewTimer(m.Lifetime + time.Second)
	// Don't defer timer.stop(), because defer is evaluated in this
	// point, but timer can be changed later on.
	// Instead, stop timer at every exit point.
	// defer timer.Stop()
	for {

		// Calculate remaining time until refresh
		remaining := session.Expiration.Sub(time.Now())
		switch {
		case remaining <= 0:
			loggerCtx.Info("Session expired without renewal")
			timer.Stop()
			return
		case remaining > 120*time.Second:
			remaining -= 60 * time.Second
		case remaining > 60*time.Second:
			remaining -= 30 * time.Second
		}
		refresh := time.NewTimer(remaining)

		select {
		// Expiration
		case <-timer.C:
			remaining := session.AccessTime.Remaining(m.Lifetime)
			if remaining <= 0 {
				loggerCtx.Info("Session thread expired")
				refresh.Stop()
				return
			}
			timer = time.NewTimer(remaining + time.Second)
		// Token refresh
		case <-refresh.C:
			token, exp, err := m.restRefresh(cred, session.Token)
			if err == nil {
				if token != "" {
					session.Expiration = exp
					session.Token = token
				}
			} else {
				loggerCtx.WithError(err).Error("Failed to refresh token")
			}
		// Cancellation
		case <-ctx.Done():
			loggerCtx.Info("Session thread context cancelled")
			timer.Stop()
			refresh.Stop()
			return
		}
	}
}

// login must be called with the mutex NOT held
func (m *AuthManager) restLogin(cred Credentials, pass string) (string, time.Time, error) {
	return "fakeToken", time.Now().Add(time.Hour), nil
}

// login must be called with the mutex NOT held
func (m *AuthManager) restRefresh(cred Credentials, pass string) (string, time.Time, error) {
	return "fakeToken", time.Now().Add(time.Hour), nil
}
