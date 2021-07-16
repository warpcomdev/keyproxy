package main

import (
	"bytes"
	"errors"
	"io"
	"net/http"

	log "github.com/sirupsen/logrus"
)

// ReplaceReader is a hack to make wso2 js work.
type ReplaceReader struct {
	Logger *log.Entry
	body   io.ReadCloser
	buffer [16]byte
	memory int
}

// Read implements io.Reader
// Replaces ("ws://" +) with ("wss://"+) in response body.
// Notice how both strings are same length, so we don't
// break the Content-Length header.
func (rb *ReplaceReader) Read(buf []byte) (int, error) {
	wrong := []byte("\"ws://\" +")
	right := []byte("\"wss://\"+")
	// If there is no room even for the memory, raise an error
	if len(buf) <= rb.memory {
		return 0, errors.New("Buffer too small")
	}
	// Copy the memory from previous read to the buffer
	if rb.memory > 0 {
		copy(buf, rb.buffer[0:rb.memory])
	}
	// Read new chunk
	n, err := rb.body.Read(buf[rb.memory:])
	total := rb.memory + n
	// If we read something new, search for replace pattern
	if n > 0 {
		rb.Logger.WithField("read", n).Debug("Reading body")
		search := buf[:total]
		ind := bytes.Index(search, wrong)
		for ind >= 0 {
			rb.Logger.Debug("performing replacement")
			search = search[ind:]
			copy(search, right)
			ind = bytes.Index(search, wrong)
		}
	}
	// If there is an error, do not keep memory
	if err != nil {
		rb.memory = 0
		return total, err
	}
	// Do not return the whole buffer, save 16 bytes to memory
	memory := 16
	if total < memory {
		return 0, errors.New("Read too small")
	}
	copy(rb.buffer[:], buf[(total-memory):total])
	total -= memory
	rb.memory = memory
	return total, err
}

// Close implementents io.ReadCloser
func (rb *ReplaceReader) Close() error {
	rb.Logger.Debug("Closing body")
	return rb.body.Close()
}

// Flush implements io.Flusher
func (rb *ReplaceReader) Flush() {
	if f, ok := rb.body.(http.Flusher); ok {
		rb.Logger.Debug("Flushing body")
		f.Flush()
	}
}
