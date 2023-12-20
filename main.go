package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strace/interceptor"
	"strace/syscalls"
	"strconv"
	"strings"
	"syscall"
)

func main() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	fmt.Printf("Run %v\n", os.Args[1:])

	cmd := exec.Command(os.Args[1], os.Args[2:]...)
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Ptrace: true,
	}

	err := cmd.Start()
	if err != nil {
		panic(fmt.Sprintf("cmd start: %v", err))
	}
	err = cmd.Wait() // cmd is paused
	if err != nil {
		var e *exec.ExitError
		if !errors.As(err, &e) || e.ProcessState.Sys().(syscall.WaitStatus).StopSignal() != syscall.SIGTRAP {
			// expected "stop signal: trace/breakpoint trap" (5)
			panic(fmt.Sprintf("expected trap: %v", err))
		}
	}

	var regs syscall.PtraceRegs
	pid := cmd.Process.Pid
	exit := true

	fileDescriptor := make(map[int]string)

	pro := provider{
		pid:            pid,
		fileDescriptor: fileDescriptor,
	}
	interceptors := map[string]interceptor.Interceptor{
		"proxy":  interceptor.NewProxy(os.Getenv("INTER_FILE"), os.Getenv("INTER_URL"), &pro),
		"writer": interceptor.NewWriter(),
	}

program:
	for {
		if err = syscall.PtraceGetRegs(pid, &regs); err != nil {
			panic(fmt.Sprintf("get regs (pid %d) err: %v\n", pid, err))
		}

		syscallNum := int(regs.Orig_rax)

		// https://man7.org/linux/man-pages/man2/syscall.2.html
		//   Arch/ABI    arg1  arg2  arg3  arg4  arg5  arg6  arg7   Notes
		//   ────────────────────────────────────────────────────────────
		//   x86-64      rdi   rsi   rdx   r10   r8    r9    -
		//
		//   Arch/ABI    Instruction       System  Ret  Ret  Error  Notes
		//                                 call #  val  val2
		//   ────────────────────────────────────────────────────────────
		//   x86-64      syscall           rax     rax  rdx  -      5

		arg1 := int(regs.Rdi)
		arg2 := int(regs.Rsi)
		arg3 := int(regs.Rdx)
		arg4 := int(regs.R10)
		arg5 := int(regs.R8)
		arg6 := int(regs.R9)

		syscallName := strings.ToLower(syscalls.GetName(syscallNum))

		if !exit {
			fmt.Printf("%s", syscallName)
			for _, inter := range interceptors {
				inter.Before(syscallNum, arg1, arg2, arg3, arg4, arg5, arg6)
			}
		} else if exit {

			retVal := int(regs.Rax)

			str := ""

			switch syscallNum {
			case syscall.SYS_GETUID, syscall.SYS_GETEUID:
				// uid_t get[e]uid(void)
				str += fmt.Sprintf(`() = %d`, retVal)
			case syscall.SYS_OPEN:
				// int open(const char *path, int oflag, ...)
				path := readPtraceText(pid, uintptr(arg1))
				fd := retVal
				str += fmt.Sprintf(`("%s", %d) = %d`, path, arg2, fd)
				fileDescriptor[fd] = path
			case syscall.SYS_READ:
				// ssize_t read(int fildes, void *buf, size_t nbyte)
				fd := formatFileDesc(fileDescriptor, arg1)
				if retVal <= arg3 {
					buf := shortString(readPtraceTextBuf(pid, uintptr(arg2), retVal))
					str += fmt.Sprintf(`(%s, %d, %d) = %d: %s`, fd, arg2, arg3, retVal, buf)
				} else {
					str += fmt.Sprintf(`(%s, %d, %d) = %d`, fd, arg2, arg3, retVal)
				}
			case syscall.SYS_LSEEK:
				// off_t lseek(int fildes, off_t offset, int whence)
				// If whence is SEEK_SET, the file offset shall be set to offset bytes.
				// If whence is SEEK_CUR, the file offset shall be set to its current location plus offset.
				// If whence is SEEK_END, the file offset shall be set to the size of the file plus offset.
				// https://pubs.opengroup.org/onlinepubs/009696799/functions/lseek.html
				fd := formatFileDesc(fileDescriptor, arg1)
				whence := map[int]string{0: "SEEK_SET", 1: "SEEK_CUR", 2: "SEEK_END"}
				str += fmt.Sprintf(`(%s, %d, %s) = %d`, fd, arg2, whence[arg3], retVal)
			case syscall.SYS_MMAP:
				// void * mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset)
				str += fmt.Sprintf(`(%d, %d, %d, %d, %d, %d)`,
					arg1, arg2, arg3, arg4, arg5, arg6)
			case syscall.SYS_WRITE:
				// ssize_t write(int fd, const void *buf, size_t count)
				buf := shortString(readPtraceTextBuf(pid, uintptr(arg2), arg3))
				str += fmt.Sprintf(`(%d, %q, %d)`, arg1, buf, arg3)
			case syscall.SYS_STAT:
				// int stat(const char *restrict pathname, struct stat *restrict statbuf)
				path := readPtraceText(pid, uintptr(arg1))
				str += fmt.Sprintf(`(%s, %d) = %d`, path, arg2, retVal)
			}

			fmt.Printf("%s\n", str)
		}

		for {
			err = syscall.PtraceSyscall(pid, 0) // wait for next syscall to begin or exit
			if err != nil {
				panic(fmt.Sprintf("ptrace err: %v", err))
			}

			// wait for process to change state
			var wstatus syscall.WaitStatus
			_, err := syscall.Wait4(pid, &wstatus, 0, nil)
			if err != nil {
				panic(fmt.Sprintf("wait4 err: %v", err))
			}
			if wstatus.Exited() {
				fmt.Printf("target process exited with code %d\n", wstatus.ExitStatus())
				break program
			}
			if wstatus.TrapCause() > -1 {
				break
			}
			fmt.Printf("wstatus: %t %t %t %t %d\n", wstatus.Continued(), wstatus.Stopped(), wstatus.Signaled(), wstatus.Exited(), wstatus.TrapCause())
		}
		exit = !exit
	}
}

func formatFileDesc(descriptors map[int]string, fd int) string {
	if path, ok := descriptors[fd]; ok {
		return fmt.Sprintf(`%d<%s>`, fd, path)
	} else {
		return strconv.Itoa(fd)
	}
}

type provider struct {
	pid            int
	fileDescriptor map[int]string
}

func (p *provider) ReadPtraceText(addr uintptr) string {
	return readPtraceText(p.pid, addr)
}

func (p *provider) FileName(fd int) string {
	f, _ := p.fileDescriptor[fd]
	return f
}

func (p *provider) FileDescriptor(filename string) int {
	for fd, name := range p.fileDescriptor {
		if name == filename {
			return fd
		}
	}
	return -1
}

func readPtraceText(pid int, addr uintptr) string {
	s := ""
	buf := []byte{1}
	for i := addr; ; i++ {
		if c, err := syscall.PtracePeekText(pid, i, buf); err != nil {
			panic(fmt.Sprintf("ptrace peek i: %v", err))
		} else if c == 0 || buf[0] == 0 {
			break
		}
		s += string(buf)
	}
	return s
}

func readPtraceTextBuf(pid int, addr uintptr, length int) string {
	buf := make([]byte, length)
	if _, err := syscall.PtracePeekText(pid, addr, buf); err != nil {
		panic(fmt.Sprintf("ptrace peek buf: %v", err))
	}
	return string(buf)
}

func shortString(buf string) interface{} {
	buf = fmt.Sprintf("%q", buf)
	if len(buf) > 40 {
		buf = buf[0:18] + `"..."` + buf[len(buf)-19:]
	}
	return buf
}
