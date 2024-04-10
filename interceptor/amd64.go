//go:build amd64

package interceptor

import "syscall"

func init() {
	syscall_OPEN = syscall.SYS_OPEN
}
