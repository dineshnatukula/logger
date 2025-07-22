package logger

import (
	"bytes"
	"io"
	"sync"
)

// Buffer is a concurrent safe implementation of bytes.Buffer
type Buffer struct {
	b bytes.Buffer
	m sync.Mutex
}

// Read is concurrent safe implementation of Read
func (b *Buffer) Read(p []byte) (n int, err error) {
	b.m.Lock()
	defer b.m.Unlock()
	return b.b.Read(p)
}

// Write concurrent safe implementation of Write
func (b *Buffer) Write(p []byte) (n int, err error) {
	b.m.Lock()
	defer b.m.Unlock()
	return b.b.Write(p)
}

// String concurrent safe implementation of String
func (b *Buffer) String() string {
	b.m.Lock()
	defer b.m.Unlock()
	return b.b.String()
}

// Bytes concurrent safe implementation of Bytes
func (b *Buffer) Bytes() []byte {
	b.m.Lock()
	defer b.m.Unlock()
	return b.b.Bytes()
}

// WriteTo writes copy of a buffer to w. Concurrent safe
func (b *Buffer) WriteTo(w io.Writer) (int64, error) {
	reader := bytes.NewReader(b.Bytes())
	b.m.Lock()
	defer b.m.Unlock()
	return io.Copy(w, reader)
}

// Cap concurrent safe implementation of Cap
func (b *Buffer) Cap() int {
	b.m.Lock()
	defer b.m.Unlock()
	return b.b.Cap()
}

// Grow concurrent safe implementation of Grow
func (b *Buffer) Grow(n int) {
	b.m.Lock()
	defer b.m.Unlock()
	b.b.Grow(n)
}

// Len concurrent safe implementation of Len
func (b *Buffer) Len() int {
	b.m.Lock()
	defer b.m.Unlock()
	return b.b.Len()
}

// Next concurrent safe implementation of Next
func (b *Buffer) Next(n int) []byte {
	b.m.Lock()
	defer b.m.Unlock()
	return b.b.Next(n)
}

// ReadByte concurrent safe implementation of ReadByte
func (b *Buffer) ReadByte() (c byte, err error) {
	b.m.Lock()
	defer b.m.Unlock()
	return b.b.ReadByte()
}

// ReadBytes concurrent safe implementation of ReadBytes
func (b *Buffer) ReadBytes(delim byte) (line []byte, err error) {
	b.m.Lock()
	defer b.m.Unlock()
	return b.b.ReadBytes(delim)
}

// ReadFrom concurrent safe implementation of ReadFrom
func (b *Buffer) ReadFrom(r io.Reader) (n int64, err error) {
	b.m.Lock()
	defer b.m.Unlock()
	return b.b.ReadFrom(r)
}

// ReadRune concurrent safe implementation of ReadRune
func (b *Buffer) ReadRune() (r rune, size int, err error) {
	b.m.Lock()
	defer b.m.Unlock()
	return b.b.ReadRune()
}

// ReadString concurrent safe implementation of ReadString
func (b *Buffer) ReadString(delim byte) (line string, err error) {
	b.m.Lock()
	defer b.m.Unlock()
	return b.b.ReadString(delim)
}

// Reset concurrent safe implementation of Reset
func (b *Buffer) Reset() {
	b.m.Lock()
	defer b.m.Unlock()
	b.b.Reset()
}

// Truncate concurrent safe implementation of Truncate
func (b *Buffer) Truncate(n int) {
	b.m.Lock()
	defer b.m.Unlock()
	b.b.Truncate(n)
}

// UnreadByte concurrent safe implementation of UnreadByte
func (b *Buffer) UnreadByte() error {
	b.m.Lock()
	defer b.m.Unlock()
	return b.b.UnreadByte()
}

// UnreadRune concurrent safe implementation of UnreadRune
func (b *Buffer) UnreadRune() error {
	b.m.Lock()
	defer b.m.Unlock()
	return b.b.UnreadRune()
}

// WriteByte concurrent safe implementation of WriteByte
func (b *Buffer) WriteByte(c byte) error {
	b.m.Lock()
	defer b.m.Unlock()
	return b.b.WriteByte(c)
}

// WriteRune concurrent safe implementation of WriteRune
func (b *Buffer) WriteRune(r rune) (n int, err error) {
	b.m.Lock()
	defer b.m.Unlock()
	return b.b.WriteRune(r)
}

// WriteString concurrent safe implementation of WriteString
func (b *Buffer) WriteString(s string) (n int, err error) {
	b.m.Lock()
	defer b.m.Unlock()
	return b.b.WriteString(s)
}
