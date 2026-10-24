package shell

import (
	"bytes"
	"sync"
)

type captureState struct {
	marker        []byte
	stdoutPending []byte
	stderrPending []byte
	stdoutDone    bool
	stderrDone    bool
	done          chan struct{}
	max           int
	stdout        bytes.Buffer
	stderr        bytes.Buffer
	truncated     bool
	total         int
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
	defer c.mu.Unlock()
	state := c.current
	if state == nil {
		return
	}
	pending := &state.stderrPending
	finished := &state.stderrDone
	if isStdout {
		pending = &state.stdoutPending
		finished = &state.stdoutDone
	}
	if *finished {
		return
	}
	*pending = append(*pending, data...)
	if index := bytes.Index(*pending, state.marker); index >= 0 {
		state.write(isStdout, (*pending)[:index])
		*pending = nil
		*finished = true
		if state.stdoutDone && state.stderrDone {
			close(state.done)
		}
		return
	}
	// Keep a possible partial marker across reads, even after output truncation.
	if count := len(*pending) - len(state.marker) + 1; count > 0 {
		state.write(isStdout, (*pending)[:count])
		*pending = append((*pending)[:0], (*pending)[count:]...)
	}
}

func (state *captureState) write(isStdout bool, data []byte) {
	remaining := state.max - state.total
	if remaining <= 0 {
		if len(data) > 0 {
			state.truncated = true
		}
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
}
