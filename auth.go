package main

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	log "github.com/sirupsen/logrus"
)

const (
	// Number of bits of te hash used for anti-bruteforce ratelimit
	LOGIN_HASH_BITS = 12
)

var ErrorTooManyAttempts = errors.New("Too many concurrent auth attempts")
var ErrorAuthCancelled = errors.New("AuthManager is being cancelled")
var ErrorInvalidWebToken = errors.New("Web Token is not valid, check your clock")

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
	// accessTime, Token and Expiration are used for session refresh
	accessTime AtomicTimestamp
	token      string
	expiration time.Time
	// hash is used for rate limiting
	hash uint32
	// logout is used for delayed logout.
	// It is protected by the AuthManager lock, not the AuthSession log.
	// i.e. AuthSession never uses it. Only AuthManager uses it,
	// and it is always used without the mutex below.
	logout bool
	// JWT is used for Auth, and protected by mutex.
	jwtToken string
	jwtError error
	mutex    sync.Mutex
}

// Update JWT Token based on credentials and time.
// The updated JWT token might be empty (""), even if
// The JWT Error is nil too.
func (s *AuthSession) updateJWT(cred Credentials, token string, expiration time.Time, method jwt.SigningMethod, keyFunc jwt.Keyfunc) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.expiration = expiration
	s.token = token
	now := time.Now()
	jwtToken := jwt.NewWithClaims(method, jwt.StandardClaims{
		ExpiresAt: s.expiration.Add(time.Minute).Unix(),
		IssuedAt:  now.Unix(),
		Issuer:    cred.Service,
		NotBefore: now.Add(-time.Minute).Unix(),
		Subject:   cred.Username,
	})
	key, err := keyFunc(jwtToken)
	if err != nil {
		s.jwtError = err
		return err
	}
	jwtString, err := jwtToken.SignedString(key)
	if err != nil {
		s.jwtError = err
		return err
	}
	s.jwtError = nil
	s.jwtToken = jwtString
	return nil
}

// JWT returns the signedJWT along with an expiration time for cookies
func (s *AuthSession) JWT() (string, time.Time, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.jwtToken, s.expiration, s.jwtError
}

// AuthManager handles credential resolution, ratelimit and cache
type AuthManager struct {
	// TimeKeeper must be at the top of the struct
	TimeKeeper
	Logger   *log.Logger
	Lifetime time.Duration
	Keystone Keystone
	// For token signing
	SigningMethod jwt.SigningMethod
	KeyFunc       jwt.Keyfunc
	// Session cache. Keeps refreshing tokens.
	cache     map[Credentials]*AuthSession
	loginHash []UnixTimestamp
}

// NewAuth creates new Auth Manager
func NewAuth(logger *log.Logger, lifetime time.Duration, keystoneURL string, signingMethod jwt.SigningMethod, keyFunc jwt.Keyfunc) *AuthManager {
	manager := &AuthManager{
		Logger:        logger,
		Lifetime:      lifetime,
		Keystone:      Keystone{URL: fmt.Sprintf("%s/v3/auth/tokens", keystoneURL)},
		SigningMethod: signingMethod,
		KeyFunc:       keyFunc,
		cache:         make(map[Credentials]*AuthSession),
		loginHash:     make([]UnixTimestamp, 1<<LOGIN_HASH_BITS),
	}
	manager.Tick(time.Second)
	return manager
}

// Check the credential cache for a match that has not expired yet.
func (m *AuthManager) Check(webToken string) (Credentials, *AuthSession, error) {
	var claims jwt.StandardClaims
	jwtToken, err := jwt.ParseWithClaims(webToken, &claims, m.KeyFunc)
	if err != nil {
		return Credentials{}, nil, err
	}
	if !jwtToken.Valid {
		return Credentials{}, nil, ErrorInvalidWebToken
	}
	cred := Credentials{Service: claims.Issuer, Username: claims.Subject}
	m.Mutex.Lock()
	defer m.Mutex.Unlock()
	session, ok := m.cache[cred]
	if !ok {
		return cred, nil, nil
	}
	if session.logout {
		return cred, nil, nil
	}
	session.accessTime.Store(m.Clock())
	return cred, session, nil
}

// Login with credentials and password.
func (m *AuthManager) Login(cred Credentials, password string) (*AuthSession, error) {
	// Rate-limit based on buckets
	credHash := cred.Hash(password)
	bitMask := credHash & ((1 << LOGIN_HASH_BITS) - 1)
	timestamp := m.Clock()
	m.Mutex.Lock()
	if m.loginHash[bitMask] >= timestamp {
		m.Mutex.Unlock()
		return nil, ErrorTooManyAttempts
	}
	m.loginHash[bitMask] = timestamp
	m.Mutex.Unlock()

	// Fill session data. This is a race, since I release the lock.
	logger := m.Logger.WithField("credentials", cred)
	token, exp, err := m.Keystone.restLogin(logger, cred, password)
	if err != nil || token == "" {
		return nil, err
	}

	// Check if session exists, update it if it does not.
	m.Mutex.Lock()
	session, existing := m.cache[cred]
	if existing {
		session.logout = false
	} else {
		session = &AuthSession{
			token:      token,
			expiration: exp,
			hash:       credHash,
			logout:     false,
		}
		session.accessTime.Store(timestamp)
		m.cache[cred] = session
		m.Group.Add(1)
		go func() {
			defer m.Group.Done()
			m.Watch(m.cancelCtx, cred, session)
		}()
	}
	m.Mutex.Unlock()
	session.updateJWT(cred, token, exp, m.SigningMethod, m.KeyFunc)
	session.accessTime.Store(m.Clock())
	return session, nil
}

func (m *AuthManager) Logout(session *AuthSession) {
	m.Mutex.Lock()
	session.logout = true
	m.Mutex.Unlock()
}

func (m *AuthManager) Watch(ctx context.Context, cred Credentials, session *AuthSession) {
	// When the watch is done, remove the session from cache
	defer func() {
		m.Mutex.Lock()
		session.logout = true
		delete(m.cache, cred)
		m.Mutex.Unlock()
	}()
	logger := m.Logger.WithField("cred", cred)
	timer := time.NewTimer(m.Lifetime + time.Second)
	// Don't defer timer.stop(), because defer is evaluated in this
	// point, but timer can be changed later on.
	// Instead, stop timer at every exit point.
	// defer timer.Stop()
	for {

		// Calculate remaining time until refresh
		remaining := session.expiration.Sub(time.Now())
		switch {
		case remaining <= 0:
			logger.Info("Session expired without renewal")
			timer.Stop()
			return
		case remaining > 240*time.Second:
			remaining -= 120 * time.Second
		case remaining > 120*time.Second:
			remaining -= 60 * time.Second
		case remaining > 60*time.Second:
			remaining -= 30 * time.Second
		}
		refresh := time.NewTimer(remaining)

		select {
		// Expiration
		case <-timer.C:
			remaining := session.accessTime.Remaining(m.Lifetime)
			if remaining <= 0 {
				logger.Info("Session thread expired")
				refresh.Stop()
				return
			}
			timer = time.NewTimer(remaining + time.Second)
		// Token refresh
		case <-refresh.C:
			token, exp, err := m.Keystone.restRefresh(logger, cred, session.token)
			if err == nil {
				if token != "" {
					session.updateJWT(cred, token, exp, m.SigningMethod, m.KeyFunc)
				} else {
					logger.Info("Failed to refresh token")
				}
			} else {
				logger.WithError(err).Error("Failed to refresh token")
			}
		// Cancellation
		case <-ctx.Done():
			logger.Info("Session thread context cancelled")
			timer.Stop()
			refresh.Stop()
			return
		}
	}
}
