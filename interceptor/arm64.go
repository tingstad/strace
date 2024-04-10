//go:build arm64 && !darwin

package interceptor

import "syscall"

func init() {
	syscall_OPEN = syscall.SYS_OPENAT
	openPathArg2 = true
}
