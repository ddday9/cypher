package engine

import (
	"bytes"
	"io"
	"sync"
)

// LogBuffer keeps the most recent log lines in memory and also copies them
// to an optional writer.
type LogBuffer struct {
	mu    sync.Mutex
	lines []string
	next  int64 // sequence number of the next line
	max   int
	out   io.Writer
	part  []byte
}

// NewLogBuffer keeps up to max lines.
func NewLogBuffer(max int, out io.Writer) *LogBuffer {
	return &LogBuffer{max: max, out: out}
}

func (b *LogBuffer) Write(p []byte) (int, error) {
	if b.out != nil {
		b.out.Write(p)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.part = append(b.part, p...)
	for {
		i := bytes.IndexByte(b.part, '\n')
		if i < 0 {
			break
		}
		b.lines = append(b.lines, string(b.part[:i]))
		b.part = b.part[i+1:]
		b.next++
		if len(b.lines) > b.max {
			b.lines = b.lines[len(b.lines)-b.max:]
		}
	}
	return len(p), nil
}

// Since returns lines with sequence number >= from, and the next number.
func (b *LogBuffer) Since(from int64) ([]string, int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	first := b.next - int64(len(b.lines))
	if from < first {
		from = first
	}
	if from >= b.next {
		return []string{}, b.next
	}
	out := append([]string{}, b.lines[from-first:]...)
	return out, b.next
}
