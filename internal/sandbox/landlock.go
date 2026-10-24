package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"
)

type Config struct {
	WriteAllow       []string
	BindTCPAllow     []uint16
	AllowOutgoingTCP bool
	AllowIOCTLDev    bool
}

func Apply(cfg Config) error {
	abi, err := llsys.LandlockGetABIVersion()
	if err != nil {
		return fmt.Errorf("landlock ABI: %w", err)
	}
	if abi < 1 {
		return fmt.Errorf("landlock ABI unsupported: %d", abi)
	}
	needNet := true
	if needNet && abi < 4 {
		return fmt.Errorf("landlock ABI %d does not support network rules", abi)
	}

	writeAllow, err := canonicalizeDirs(cfg.WriteAllow)
	if err != nil {
		return err
	}

	var fsHandled uint64
	fsHandled = llsys.AccessFSExecute | llsys.AccessFSReadFile | llsys.AccessFSReadDir |
		llsys.AccessFSWriteFile | llsys.AccessFSRemoveFile | llsys.AccessFSRemoveDir |
		llsys.AccessFSMakeReg | llsys.AccessFSMakeDir | llsys.AccessFSMakeSym |
		llsys.AccessFSMakeChar | llsys.AccessFSMakeBlock | llsys.AccessFSMakeFifo | llsys.AccessFSMakeSock
	if abi >= 2 {
		fsHandled |= llsys.AccessFSRefer
	}
	if abi >= 3 {
		fsHandled |= llsys.AccessFSTruncate
	}
	if abi >= 5 && cfg.AllowIOCTLDev {
		fsHandled |= llsys.AccessFSIoctlDev
	}

	var netHandled uint64
	netHandled |= llsys.AccessNetBindTCP
	if !cfg.AllowOutgoingTCP {
		netHandled |= llsys.AccessNetConnectTCP
	}

	attr := llsys.RulesetAttr{
		HandledAccessFS:  fsHandled,
		HandledAccessNet: netHandled,
	}
	rulesetFD, err := llsys.LandlockCreateRuleset(&attr, 0)
	if err != nil {
		return fmt.Errorf("landlock create ruleset: %w", err)
	}
	defer unix.Close(rulesetFD)

	rootFD, err := openPath("/")
	if err != nil {
		return err
	}
	if err := addPathRule(rulesetFD, rootFD, roAccess(abi, cfg.AllowIOCTLDev)); err != nil {
		unix.Close(rootFD)
		return err
	}
	unix.Close(rootFD)

	for _, dir := range writeAllow {
		fd, err := openPath(dir)
		if err != nil {
			return err
		}
		if err := addPathRule(rulesetFD, fd, rwAccess(abi, cfg.AllowIOCTLDev)); err != nil {
			unix.Close(fd)
			return err
		}
		unix.Close(fd)
	}

	for _, port := range cfg.BindTCPAllow {
		attr := llsys.NetPortAttr{
			AllowedAccess: llsys.AccessNetBindTCP,
			Port:          uint64(port),
		}
		if err := llsys.LandlockAddNetPortRule(rulesetFD, &attr, 0); err != nil {
			return fmt.Errorf("landlock add net port rule: %w", err)
		}
	}

	// Go can fork a child from any runtime thread. Restricting only this
	// goroutine's current thread leaves siblings (and their children) unconfined.
	if err := llsys.AllThreadsPrctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl no_new_privs: %w", err)
	}
	if err := llsys.AllThreadsLandlockRestrictSelf(rulesetFD, 0); err != nil {
		return fmt.Errorf("landlock restrict self: %w", err)
	}
	return nil
}

func roAccess(abi int, allowIOCTL bool) uint64 {
	access := uint64(llsys.AccessFSExecute | llsys.AccessFSReadFile | llsys.AccessFSReadDir)
	if abi >= 5 && allowIOCTL {
		access |= llsys.AccessFSIoctlDev
	}
	return access
}

func rwAccess(abi int, allowIOCTL bool) uint64 {
	access := roAccess(abi, allowIOCTL) | llsys.AccessFSWriteFile |
		llsys.AccessFSRemoveFile | llsys.AccessFSRemoveDir |
		llsys.AccessFSMakeReg | llsys.AccessFSMakeDir | llsys.AccessFSMakeSym |
		llsys.AccessFSMakeChar | llsys.AccessFSMakeBlock | llsys.AccessFSMakeFifo | llsys.AccessFSMakeSock
	if abi >= 2 {
		access |= llsys.AccessFSRefer
	}
	if abi >= 3 {
		access |= llsys.AccessFSTruncate
	}
	return access
}

func addPathRule(rulesetFD int, parentFD int, access uint64) error {
	attr := llsys.PathBeneathAttr{
		AllowedAccess: access,
		ParentFd:      parentFD,
	}
	if err := llsys.LandlockAddPathBeneathRule(rulesetFD, &attr, 0); err != nil {
		return fmt.Errorf("landlock add path rule: %w", err)
	}
	return nil
}

func openPath(path string) (int, error) {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open path %s: %w", path, err)
	}
	return fd, nil
}

func canonicalizeDirs(dirs []string) ([]string, error) {
	out := make([]string, 0, len(dirs))
	for _, dir := range dirs {
		if strings.TrimSpace(dir) == "" {
			continue
		}
		clean := filepath.Clean(dir)
		resolved, err := filepath.EvalSymlinks(clean)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", dir, err)
		}
		info, err := os.Stat(resolved)
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", resolved, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("%s is not a directory", resolved)
		}
		out = append(out, resolved)
	}
	return out, nil
}
