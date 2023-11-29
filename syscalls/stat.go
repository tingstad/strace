//go:build !freebsd && !solaris && !(linux && arm64) && !(linux && loong64) && !(linux && riscv64)

package syscalls

import "syscall"

func init() {
	syscallNames[syscall.SYS_STAT] = "STAT"
}
