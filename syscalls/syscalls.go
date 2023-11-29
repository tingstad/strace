package syscalls

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"log"
	"strconv"
	"strings"
	"syscall"
)

func GetName(syscallID uint64) string {
	if name, ok := syscallNames[int(syscallID)]; ok {
		return name
	} else {
		return fmt.Sprintf("_%d_", syscallID)
	}
}

func init() {
	src := `package main
		import "syscall"
		
		const foo = syscall.SYS_WRITE`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "src.go", src, 0)
	if err != nil {
		log.Fatal(err) // parse error
	}
	conf := types.Config{Importer: importer.Default()}
	pkg, err := conf.Check("a/path", fset, []*ast.File{f}, nil)
	if err != nil {
		log.Fatal(err) // type error
	}
	scope := pkg.Imports()[0].Scope() // "syscall" import
	for _, name := range scope.Names() {
		if !strings.HasPrefix(name, "SYS_") {
			continue
		}
		obj := scope.Lookup(name)
		if c, ok := obj.(*types.Const); ok {
			i, err := strconv.Atoi(c.Val().String())
			if err != nil {
				continue
			}
			syscallNames[i] = strings.TrimPrefix(name, "SYS_")
		}
	}
}

// common UNIX system calls, present in all of
// zsysnum_{darwin,dragonfly,freebsd,linux,netbsd,openbsd}_*
var syscallNames = map[int]string{
	//syscall.SYS_ACCT:         "ACCT",
	syscall.SYS_CHDIR:        "CHDIR",
	syscall.SYS_CHROOT:       "CHROOT",
	syscall.SYS_CLOSE:        "CLOSE",
	syscall.SYS_DUP:          "DUP",
	syscall.SYS_EXECVE:       "EXECVE",
	syscall.SYS_EXIT:         "EXIT",
	syscall.SYS_FCHDIR:       "FCHDIR",
	syscall.SYS_FCHMOD:       "FCHMOD",
	syscall.SYS_FCHOWN:       "FCHOWN",
	syscall.SYS_FCNTL:        "FCNTL",
	syscall.SYS_FLOCK:        "FLOCK",
	syscall.SYS_FSYNC:        "FSYNC",
	syscall.SYS_FTRUNCATE:    "FTRUNCATE",
	syscall.SYS_GETEGID:      "GETEGID",
	syscall.SYS_GETEUID:      "GETEUID",
	syscall.SYS_GETGID:       "GETGID",
	syscall.SYS_GETGROUPS:    "GETGROUPS",
	syscall.SYS_GETITIMER:    "GETITIMER",
	syscall.SYS_GETPGID:      "GETPGID",
	syscall.SYS_GETPID:       "GETPID",
	syscall.SYS_GETPPID:      "GETPPID",
	syscall.SYS_GETPRIORITY:  "GETPRIORITY",
	syscall.SYS_GETRUSAGE:    "GETRUSAGE",
	syscall.SYS_GETSID:       "GETSID",
	syscall.SYS_GETTIMEOFDAY: "GETTIMEOFDAY",
	syscall.SYS_GETUID:       "GETUID",
	syscall.SYS_IOCTL:        "IOCTL",
	syscall.SYS_KILL:         "KILL",
	syscall.SYS_LSEEK:        "LSEEK",
	syscall.SYS_MADVISE:      "MADVISE",
	syscall.SYS_MLOCK:        "MLOCK",
	syscall.SYS_MLOCKALL:     "MLOCKALL",
	syscall.SYS_MMAP:         "MMAP",
	syscall.SYS_MOUNT:        "MOUNT",
	syscall.SYS_MPROTECT:     "MPROTECT",
	syscall.SYS_MUNLOCK:      "MUNLOCK",
	syscall.SYS_MUNLOCKALL:   "MUNLOCKALL",
	syscall.SYS_MUNMAP:       "MUNMAP",
	syscall.SYS_PTRACE:       "PTRACE",
	syscall.SYS_READ:         "READ",
	syscall.SYS_READV:        "READV",
	syscall.SYS_REBOOT:       "REBOOT",
	syscall.SYS_SETGID:       "SETGID",
	syscall.SYS_SETGROUPS:    "SETGROUPS",
	syscall.SYS_SETITIMER:    "SETITIMER",
	syscall.SYS_SETPGID:      "SETPGID",
	syscall.SYS_SETPRIORITY:  "SETPRIORITY",
	syscall.SYS_SETREGID:     "SETREGID",
	syscall.SYS_SETREUID:     "SETREUID",
	syscall.SYS_SETSID:       "SETSID",
	syscall.SYS_SETTIMEOFDAY: "SETTIMEOFDAY",
	syscall.SYS_SETUID:       "SETUID",
	syscall.SYS_SYNC:         "SYNC",
	syscall.SYS_TRUNCATE:     "TRUNCATE",
	syscall.SYS_UMASK:        "UMASK",
	syscall.SYS_WAIT4:        "WAIT4",
	syscall.SYS_WRITE:        "WRITE",
	syscall.SYS_WRITEV:       "WRITEV",
}
