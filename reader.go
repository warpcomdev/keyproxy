package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	log "github.com/sirupsen/logrus"
)

// MEMORY_BUFFER_SIZE is the amount of bytes to carry in the memory buffer
const MEMORY_BUFFER_SIZE = 16

// ErrorBufferTooSmall raised when reader has no room
type ErrorBufferTooSmall string

func (err ErrorBufferTooSmall) Error() string {
	return string(err)
}

// ReplaceReader is a hack to make wso2 js work.
type ReplaceReader struct {
	Logger *log.Entry
	body   io.ReadCloser
	memory int
	buffer [MEMORY_BUFFER_SIZE]byte
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
		return 0, ErrorBufferTooSmall(fmt.Sprintf("Buffer too small (%d)", len(buf)))
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
		search := buf[:total]
		ind := bytes.Index(search, wrong)
		for ind >= 0 {
			rb.Logger.Debug("performing replacement")
			search = search[ind:]
			copy(search, right)
			ind = bytes.Index(search, wrong)
		}
	}
	rb.memory = 0
	// If there is an error, do not keep memory
	if err != nil {
		return total, err
	}
	// Do not return the whole buffer, save MEMORY_BUFFER_SIZE bytes to memory
	memory := MEMORY_BUFFER_SIZE
	if total <= memory {
		return 0, ErrorBufferTooSmall(fmt.Sprintf("Read too small (%d)", total))
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
