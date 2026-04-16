//go:build darwin && cgo

package orchestrator

/*
#include <sandbox.h>
#include <stdlib.h>

#ifndef SANDBOX_NAMED_BUILTIN
#define SANDBOX_NAMED_BUILTIN 2
#endif

// Suppress the macOS 10.8 deprecation warning for sandbox_init.
// The API still works; Apple simply never provided a replacement.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
static int call_sandbox_init(const char *profile, uint32_t flags, char **errorbuf) {
    return sandbox_init(profile, flags, errorbuf);
}
#pragma GCC diagnostic pop
*/
import "C"

import (
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/olekukonko/ll"
)

type jobLimits struct{}

func assignToJob(_ *jobLimits, _ int) error { return nil }
func cleanupJob(_ *jobLimits)               {}

func setupProcessGroup(cmd *exec.Cmd, dropPrivileges bool) (*jobLimits, error) {
	attr := &syscall.SysProcAttr{Setpgid: true}
	if dropPrivileges {
		attr.Credential = &syscall.Credential{
			Uid: uint32(65534),
			Gid: uint32(65534),
		}
	}
	cmd.SysProcAttr = attr
	return nil, nil
}

func killProcessGroup(pid int) error {
	syscall.Kill(-pid, syscall.SIGTERM)
	go func() {
		<-time.After(10 * time.Second)
		syscall.Kill(-pid, syscall.SIGKILL)
	}()
	return nil
}

func applyCgroups(_ int, _ string, _ *ll.Logger) error { return nil }

func applySandbox(workDir string, logger *ll.Logger) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	sanitized := strings.ReplaceAll(workDir, `"`, `\"`)
	profile := fmt.Sprintf(`
(version 1)
(deny default)
(allow file-read-metadata)
(allow file-read*
	(regex #"^%s(/.*)?$")
	(regex #"^/usr/lib(/.*)?$")
	(regex #"^/System/Library(/.*)?$")
	(regex #"^/bin(/.*)?$")
	(regex #"^/usr/bin(/.*)?$")
)
(allow file-write*
	(regex #"^%s(/.*)?$")
)
(allow process-exec
	(regex #"^/usr/bin/(/.*)?$")
	(regex #"^/bin/(/.*)?$")
)
(allow sysctl-read)
(allow system-kext-query)
`, regexp.QuoteMeta(sanitized), regexp.QuoteMeta(sanitized))

	cProfile := C.CString(profile)
	defer C.free(unsafe.Pointer(cProfile))

	var errmsg *C.char
	ret := C.call_sandbox_init(cProfile, C.SANDBOX_NAMED_BUILTIN, &errmsg)
	if ret != 0 {
		if errmsg != nil {
			err := fmt.Errorf("seatbelt failed: %s", C.GoString(errmsg))
			C.free(unsafe.Pointer(errmsg))
			return err
		}
		return fmt.Errorf("seatbelt initialization failed")
	}

	logger.Fields("workDir", workDir).Debug("seatbelt sandbox applied")
	return nil
}
