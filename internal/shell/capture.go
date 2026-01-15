package shell

import (
	"bytes"
	"sync"
)

type captureState struct {
	max       int
	stdout    bytes.Buffer
	stderr    bytes.Buffer
	truncated bool
	total     int
}

type captureSlot struct {
	mu      sync.Mutex
	current *captureState
}

func (c *captureSlot) set(state *captureState) {
	c.mu.Lock()
	c.current = state
	c.mu.Unlock()
}

func (c *captureSlot) clear() {
	c.mu.Lock()
	c.current = nil
	c.mu.Unlock()
}

func (c *captureSlot) append(isStdout bool, data []byte) {
	c.mu.Lock()
	state := c.current
	if state == nil {
		c.mu.Unlock()
		return
	}
	remaining := state.max - state.total
	if remaining <= 0 {
		state.truncated = true
		c.mu.Unlock()
		return
	}
	if len(data) > remaining {
		data = data[:remaining]
		state.truncated = true
	}
	if isStdout {
		state.stdout.Write(data)
	} else {
		state.stderr.Write(data)
	}
	state.total += len(data)
	c.mu.Unlock()
}
