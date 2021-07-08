package main

import (
	log "github.com/sirupsen/logrus"
)

func Auth(logger *log.Entry, service, user, pass string) (bool, error) {
	return true, nil
}
