package sandbox

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPolicyCoversExistingAndNewThreads(t *testing.T) {
	if os.Getenv("GPTSH_SANDBOX_TEST_CHILD") != "1" {
		base := t.TempDir()
		if err := os.Mkdir(filepath.Join(base, "allowed"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, "denied"), []byte("canary"), 0600); err != nil {
			t.Fatal(err)
		}
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(exe, "-test.run=^TestPolicyCoversExistingAndNewThreads$", "-test.v")
		cmd.Env = append(os.Environ(), "GPTSH_SANDBOX_TEST_CHILD=1", "GPTSH_SANDBOX_TEST_BASE="+base)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("sandbox subprocess: %v\n%s", err, out)
		}
		return
	}
	base := os.Getenv("GPTSH_SANDBOX_TEST_BASE")
	ready, start := make(chan struct{}, 4), make(chan struct{})
	results := make(chan error, 8)
	probe := func() {
		fd, err := unix.Open(filepath.Join(base, "denied"), unix.O_WRONLY, 0)
		if err == nil {
			_ = unix.Close(fd)
		}
		if !errors.Is(err, unix.EACCES) && !errors.Is(err, unix.EPERM) {
			results <- errors.New("thread can open a protected file for writing")
			return
		}
		results <- nil
	}
	for range 4 {
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			ready <- struct{}{}
			<-start
			probe()
		}()
	}
	for range 4 {
		<-ready
	}
	if err := Apply(Config{WriteAllow: []string{filepath.Join(base, "allowed")}}); err != nil {
		t.Fatal(err)
	}
	close(start)
	for range 4 {
		go probe()
	}
	for range 8 {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
	if err := os.WriteFile(filepath.Join(base, "allowed", "ok"), []byte("ok"), 0600); err != nil {
		t.Fatal("allowed write denied:", err)
	}
}
