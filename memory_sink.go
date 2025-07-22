package logger

import (
	"io"
	"sync"
	"time"
)

// Sink is a default buffer where logs are written to
var sink *memorySink

// MemorySink implements zap.Sink by writing all messages to a buffer.
type memorySink struct {
	*Buffer
	*sync.Mutex
	size int
	done chan struct{}
}

// NewMemorySink creates buffier with given size in MB
func newMemorySink(bufferSize uint) *memorySink {
	s := &memorySink{
		Buffer: new(Buffer),
	}

	if bufferSize == 0 {
		s.size = 1 << 20
	} else {
		s.size = int(bufferSize) * 1 << 20
	}

	s.done = make(chan struct{})

	s.cutBufferTicker()

	return s
}

// Implement Close and Sync as no-op to satisfy the interface. The Write
// method is provided by the embedded buffer.

// Close clear buffer and stops cutBufferTicker
func (s *memorySink) Close() error {
	close(s.done)
	return nil
}

// Sync ...
func (s *memorySink) Sync() error {

	return nil
}

// cutBufferTicker cuts (read) log buffer to given size, default is 8MB
func (s *memorySink) cutBufferTicker() {
	ticker := time.NewTicker(2 * time.Second)
	go func() {
		for {
			select {
			case <-ticker.C:
				if s.Len() > s.size {
					p := make([]byte, s.Len()-s.size)
					s.Read(p)          // read buffer over the limit....
					s.ReadString('\n') // ... to the end of the line
				}
			case <-s.done:
				return
			}

		}
	}()
}

// copy buffer (to avoid reset buffer when read), and then write to w.
func (s *memorySink) writeCopyTo(w io.Writer) error {
	_, err := s.WriteTo(w)

	return err
}
