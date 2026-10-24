package shell

import (
	"fmt"
	"strings"
	"testing"
)

func TestOutputBarriersAndPersistentState(t *testing.T) {
	bash, err := Start("/bin/bash")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bash.Close() })
	for i := range 100 {
		cmd := fmt.Sprintf("export GPTSH_CHECK=%d; printf 'out-%%s' \"$GPTSH_CHECK\"; printf 'err-%%s' \"$GPTSH_CHECK\" >&2", i)
		out, stderr, code, _, truncated, _, err := bash.Exec(cmd, 50000)
		if err != nil || code != 0 || truncated || out != fmt.Sprintf("out-%d", i) || stderr != fmt.Sprintf("err-%d", i) {
			t.Fatalf("iteration %d: out=%q stderr=%q exit=%d truncated=%t err=%v", i, out, stderr, code, truncated, err)
		}
	}
	out, _, _, _, _, _, err := bash.Exec("echo $GPTSH_CHECK", 50000)
	if err != nil || out != "99\n" {
		t.Fatalf("state lost: %q %v", out, err)
	}
	out, _, _, _, truncated, _, err := bash.Exec("printf '1234567890'", 4)
	if err != nil || !truncated || out != "1234" {
		t.Fatalf("truncation: %q %t %v", out, truncated, err)
	}
	out, _, _, _, _, _, err = bash.Exec("echo after-truncation", 50000)
	if err != nil || strings.TrimSpace(out) != "after-truncation" {
		t.Fatalf("barrier lost after truncation: %q %v", out, err)
	}
}

func TestSplitMarkers(t *testing.T) {
	marker := []byte("\x1eGPTSH_END_test\x1f")
	state := &captureState{max: 4, marker: marker, done: make(chan struct{})}
	var slot captureSlot
	slot.set(state)
	for _, stream := range []bool{true, false} {
		for _, b := range append([]byte("abc"), marker...) {
			slot.append(stream, []byte{b})
		}
	}
	select {
	case <-state.done:
	default:
		t.Fatal("split marker was not recognized")
	}
	if state.stdout.String() != "abc" || state.stderr.String() != "a" || !state.truncated {
		t.Fatalf("incorrect capture: %+v", state)
	}
}
