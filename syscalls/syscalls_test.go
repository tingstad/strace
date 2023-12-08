package syscalls

import (
	"syscall"
	"testing"
)

func TestGetName(t *testing.T) {
	syscallID := syscall.SYS_EXECVE
	if name, expected := GetName(uint64(syscallID)), "EXECVE"; name != expected {
		t.Errorf("expected %s for %d, but got %s", expected, syscallID, name)
	}
}

func TestGetNameFromImport(t *testing.T) {
	syscallID := syscall.SYS_ACCT
	if name, expected := GetName(uint64(syscallID)), "ACCT"; name != expected {
		t.Errorf("expected %s for %d, but got %s", expected, syscallID, name)
	}
}
