package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"text/template"

	log "github.com/sirupsen/logrus"
)

type Credentials struct {
	Service  string
	Username string
}

// Hash() is not thread safe, beware...
func (c *Credentials) Hash(password string) string {
	h := sha256.New()
	h.Write([]byte(c.Service))
	h.Write([]byte(c.Username))
	h.Write([]byte(password))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

type PodFactory struct {
	Logger   *log.Logger
	Template *template.Template
	Scheme   string
	Port     int
	Managers map[Credentials]*PodManager
	mutex    sync.Mutex
}

// Find manager for the given credentials. Password is needed
func (f *PodFactory) Find(api *KubeAPI, creds Credentials) (*PodManager, error) {
	mgr, ok := f.Managers[creds]
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if ok {
		return mgr, nil
	}
	mgr, err := f.newManager(api, creds)
	if err != nil {
		return nil, err
	}
	f.Managers[creds] = mgr
	return mgr, nil
}

func (f *PodFactory) newManager(api *KubeAPI, creds Credentials) (*PodManager, error) {
	buffer := &bytes.Buffer{}
	if err := f.Template.Execute(buffer, creds); err != nil {
		return nil, err
	}
	pod, err := api.Decode(buffer.String())
	if err != nil {
		return nil, err
	}
	return &PodManager{
		Logger:     f.Logger,
		Descriptor: pod,
		Scheme:     f.Scheme,
		Port:       f.Port,
	}, nil
}
