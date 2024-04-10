package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strace/interceptor"
	"strace/syscalls"
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
	interceptors := []interceptor.Interceptor{
		interceptor.Writer(&pro),
		interceptor.Proxy(os.Getenv("FILE"), os.Getenv("URL"), &pro),
	}

program:
	for {
		if err = syscall.PtraceGetRegs(pid, &regs); err != nil {
			panic(fmt.Sprintf("get regs (pid %d) err: %v\n", pid, err))
		}

		r := syscalls.MapRegs(regs)

		syscallNum := r.SyscallNum

		arg1 := r.Arg1
		arg2 := r.Arg2
		arg3 := r.Arg3
		arg4 := r.Arg4
		arg5 := r.Arg5
		arg6 := r.Arg6

		if !exit {
			for _, inter := range interceptors {
				inter.Before(syscallNum, arg1, arg2, arg3, arg4, arg5, arg6)
			}
		} else {
			retVal := r.RetVal
			for _, inter := range interceptors {
				inter.After(syscallNum, arg1, arg2, arg3, arg4, arg5, arg6, retVal)
			}
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

type provider struct {
	pid            int
	fileDescriptor map[int]string
}

func (p *provider) PutFileDescriptor(fd int, path string) {
	p.fileDescriptor[fd] = path
}

func (p *provider) ReadPtraceText(addr uintptr) string {
	return readPtraceText(p.pid, addr)
}

func (p *provider) ReadPtraceTextBuf(addr uintptr, size int) string {
	return readPtraceTextBuf(p.pid, addr, size)
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
