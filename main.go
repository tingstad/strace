package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strace/proxy"
	"strace/syscalls"
	"strconv"
	"strings"
	"syscall"
)

func main() {
	fmt.Printf("Run %v\n", os.Args[1:])

	cmd := exec.Command(os.Args[1], os.Args[2:]...)
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Ptrace: true,
	}

	cmd.Start()
	err := cmd.Wait() // cmd is paused
	if err != nil {
		var e *exec.ExitError
		if !errors.As(err, &e) || e.ProcessState.Sys().(syscall.WaitStatus).StopSignal() != syscall.SIGTRAP {
			panic(err) // expected "stop signal: trace/breakpoint trap" (5)
		}
	}

	var regs syscall.PtraceRegs
	pid := cmd.Process.Pid
	exit := true

	proxy := proxy.New("file.zip", "https://i.ting.st/pg2701.epub")

	fileDescriptor := make(map[uint64]string)

	for {
		if err = syscall.PtraceGetRegs(pid, &regs); err != nil {
			var e syscall.Errno
			if errors.As(err, &e) && e == syscall.ESRCH { // "no such process" (3)
				break
			}
			panic(err)
		}

		syscallNum := int(regs.Orig_rax)

		if exit || true {

			// https://man7.org/linux/man-pages/man2/syscall.2.html
			//   Arch/ABI    arg1  arg2  arg3  arg4  arg5  arg6  arg7   Notes
			//   ────────────────────────────────────────────────────────────
			//   x86-64      rdi   rsi   rdx   r10   r8    r9    -
			//
			//   Arch/ABI    Instruction       System  Ret  Ret  Error  Notes
			//                                 call #  val  val2
			//   ────────────────────────────────────────────────────────────
			//   x86-64      syscall           rax     rax  rdx  -      5

			str := strings.ToLower(syscalls.GetName(syscallNum))

			var arg1 uint64 = regs.Rdi
			var arg2 uint64 = regs.Rsi
			var arg3 uint64 = regs.Rdx
			var arg4 uint64 = regs.R10
			var arg5 uint64 = regs.R8
			var arg6 uint64 = regs.R9
			var retVal uint64 = regs.Rax

			switch syscallNum {
			case syscall.SYS_GETUID, syscall.SYS_GETEUID:
				// uid_t get[e]uid(void)
				str += fmt.Sprintf(`() = %d`, retVal)
			case syscall.SYS_OPEN:
				// int open(const char *path, int oflag, ...)
				path := readPtraceText(pid, uintptr(arg1))
				if !exit && proxy.Size < 0 && path == proxy.Filename {
					proxy.Open()
				}
				fd := retVal
				str += fmt.Sprintf(`("%s", %d) = %d`, path, arg2, fd)
				fileDescriptor[fd] = fmt.Sprintf(`%d<%s>`, fd, path)
				if exit && path == proxy.Filename {
					proxy.Fd = int(fd)
				}
			case syscall.SYS_READ:
				// ssize_t read(int fildes, void *buf, size_t nbyte)
				fd := fileDescriptor[arg1]
				if retVal <= arg3 {
					buf := readPtraceTextBuf(pid, uintptr(arg2), int(retVal))
					buf = fmt.Sprintf("%q", buf)
					if len(buf) > 40 {
						buf = buf[0:18] + `"..."` + buf[len(buf)-19:]
					}
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
				fd := fileDescriptor[arg1]
				whence := map[int]string{0: "SEEK_SET", 1: "SEEK_CUR", 2: "SEEK_END"}
				str += fmt.Sprintf(`(%s, %d, %s) = %d`, fd, arg2, whence[int(arg3)], retVal)
				if v, ok := whence[int(arg3)]; ok && !exit && v == "SEEK_END" {
					if proxy.Size == -1 {
						fmt.Println("INTERCEPT - GET SIZE")
						proxy.GetSize()
					}
					proxy.Cursor = proxy.Size + int64(arg2)
					fmt.Println("INTERCEPT - SET CURSOR TO " + strconv.Itoa(int(proxy.Cursor)))
				}
			case syscall.SYS_MMAP:
				// void * mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset)
				str += fmt.Sprintf(`(%d, %d, %d, %d, %d, %d)`,
					arg1, arg2, arg3, arg4, arg5, arg6)
			case syscall.SYS_WRITE:
				// ssize_t write(int fd, const void *buf, size_t count)
				buf := readPtraceTextBuf(pid, uintptr(arg2), int(arg3))
				str += fmt.Sprintf(`(%d, %q, %d)`, arg1, buf, arg3)
			case syscall.SYS_STAT:
				// int stat(const char *restrict pathname, struct stat *restrict statbuf)
				path := readPtraceText(pid, uintptr(arg1))
				str += fmt.Sprintf(`(%s, %d) = %d`, path, arg2, retVal)

			}

			state := "PRE"
			if exit {
				state = "EPI"
			}

			fmt.Printf("%s: %s\n", state, str)
			fmt.Printf("%s\n", str)
		}

		err = syscall.PtraceSyscall(pid, 0) // wait for next syscall to begin or exit
		if err != nil {
			panic(err)
		}

		_, err = syscall.Wait4(pid, nil, 0, nil)
		if err != nil {
			panic(err)
		}

		exit = !exit
	}
}

func readPtraceText(pid int, addr uintptr) string {
	s := ""
	buf := []byte{1}
	for i := addr; ; i++ {
		if c, err := syscall.PtracePeekText(pid, i, buf); err != nil {
			panic(err)
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
		panic(err)
	}
	return string(buf)
}
