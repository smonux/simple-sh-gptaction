package shell

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	controlBegin = "BEGIN"
	controlEnd   = "END"
)

type Bash struct {
	cmd      *exec.Cmd
	stdin    io.WriteCloser
	ctrl     *bufio.Reader
	capture  captureSlot
	mu       sync.Mutex
	closedMu sync.Mutex
	closed   bool
}

func Start(path string) (*Bash, error) {
	ctrlR, ctrlW, err := os.Pipe()
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(path, "--noprofile", "--norc")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	cmd.ExtraFiles = []*os.File{ctrlW}

	if err := cmd.Start(); err != nil {
		return nil, err
	}
	_ = ctrlW.Close()

	b := &Bash{
		cmd:   cmd,
		stdin: stdin,
		ctrl:  bufio.NewReader(ctrlR),
	}

	go b.drain(stdout, true)
	go b.drain(stderr, false)

	return b, nil
}

func (b *Bash) Close() error {
	b.closedMu.Lock()
	if b.closed {
		b.closedMu.Unlock()
		return nil
	}
	b.closed = true
	b.closedMu.Unlock()

	_ = b.stdin.Close()
	if b.cmd.Process != nil {
		_ = b.cmd.Process.Kill()
	}
	return b.cmd.Wait()
}

func (b *Bash) Exec(cmd string, maxOutput int) (string, string, int, string, bool, int64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	state := &captureState{max: maxOutput}
	b.capture.set(state)
	defer b.capture.clear()

	token := randToken()
	delim := "__GPTSH_" + token + "__"

	wrapper := fmt.Sprintf("__GPTSH_T=\"%s\"\n__DELIM=\"%s\"\nprintf 'BEGIN\\t%%s\\n' \"$__GPTSH_T\" >&3\n__CMD=$(cat <<'%s'\n%s\n%s\n)\neval \"$__CMD\"\n__EC=$?\nprintf 'END\\t%%s\\t%%d\\t%%s\\n' \"$__GPTSH_T\" \"$__EC\" \"$PWD\" >&3\n", token, delim, delim, cmd, delim)

	start := time.Now()
	if _, err := io.WriteString(b.stdin, wrapper); err != nil {
		return "", "", -1, "", false, 0, err
	}

	if err := b.waitForBegin(token); err != nil {
		return "", "", -1, "", false, 0, err
	}
	cwd, exitCode, err := b.waitForEnd(token)
	if err != nil {
		return "", "", -1, "", false, 0, err
	}
	elapsed := time.Since(start).Milliseconds()
	return state.stdout.String(), state.stderr.String(), exitCode, cwd, state.truncated, elapsed, nil
}

func (b *Bash) waitForBegin(token string) error {
	for {
		line, err := b.ctrl.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimRight(line, "\n")
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}
		if parts[0] == controlBegin && parts[1] == token {
			return nil
		}
	}
}

func (b *Bash) waitForEnd(token string) (string, int, error) {
	for {
		line, err := b.ctrl.ReadString('\n')
		if err != nil {
			return "", -1, err
		}
		line = strings.TrimRight(line, "\n")
		parts := strings.SplitN(line, "\t", 4)
		if len(parts) != 4 {
			continue
		}
		if parts[0] != controlEnd || parts[1] != token {
			continue
		}
		exitCode, err := strconv.Atoi(parts[2])
		if err != nil {
			return "", -1, fmt.Errorf("invalid exit code %q", parts[2])
		}
		return parts[3], exitCode, nil
	}
}

func (b *Bash) drain(r io.Reader, isStdout bool) {
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			b.capture.append(isStdout, buf[:n])
		}
		if err != nil {
			return
		}
	}
}

func randToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
