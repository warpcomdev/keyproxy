package main

import (
	log "github.com/sirupsen/logrus"
)

func Auth(logger *log.Entry, cred Credentials, pass string) (bool, error) {
	return true, nil
}
