package interceptor

import (
	"fmt"
	"strace/syscalls"
	"strconv"
	"strings"
	"syscall"
)

type writer struct {
	provider Provider
	path     string
}

func Writer(provider Provider) *writer {
	return &writer{provider, ""}
}

func (w *writer) Before(syscallNum, arg1, arg2, arg3, arg4, arg5, arg6 int) {
	syscallName := strings.ToLower(syscalls.GetName(syscallNum))

	fmt.Printf("%s", syscallName)

	str := ""

	switch syscallNum {
	case syscall.SYS_GETUID, syscall.SYS_GETEUID:
		// uid_t get[e]uid(void)
		str += fmt.Sprintf(`() `)
	case syscall.SYS_OPEN:
		// int open(const char *path, int oflag, ...)
		w.path = w.provider.ReadPtraceText(uintptr(arg1))
		str += fmt.Sprintf(`("%s", %d) `, w.path, arg2)
	case syscall.SYS_READ:
		// ssize_t read(int fildes, void *buf, size_t nbyte)
		fd := formatFileDesc(arg1, w.provider.FileName(arg1))
		str += fmt.Sprintf("(%s, %d, %d)\n", fd, arg2, arg3)
	case syscall.SYS_LSEEK:
		// off_t lseek(int fildes, off_t offset, int whence)
		// If whence is SEEK_SET, the file offset shall be set to offset bytes.
		// If whence is SEEK_CUR, the file offset shall be set to its current location plus offset.
		// If whence is SEEK_END, the file offset shall be set to the size of the file plus offset.
		// https://pubs.opengroup.org/onlinepubs/009696799/functions/lseek.html
		fd := formatFileDesc(arg1, w.provider.FileName(arg1))
		whence := map[int]string{0: "SEEK_SET", 1: "SEEK_CUR", 2: "SEEK_END"}
		str += fmt.Sprintf(`(%s, %d, %s) `, fd, arg2, whence[arg3])
	case syscall.SYS_MMAP:
		// void * mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset)
		str += fmt.Sprintf("(%d, %d, %d, %d, %d, %d)\n",
			arg1, arg2, arg3, arg4, arg5, arg6)
	case syscall.SYS_WRITE:
		// ssize_t write(int fd, const void *buf, size_t count)
		buf := shortString(w.provider.ReadPtraceTextBuf(uintptr(arg2), arg3))
		str += fmt.Sprintf(`(%d, %q, %d) `, arg1, buf, arg3)
	case syscall.SYS_STAT:
		// int stat(const char *restrict pathname, struct stat *restrict statbuf)
		path := w.provider.ReadPtraceText(uintptr(arg1))
		str += fmt.Sprintf(`(%s, %d) `, path, arg2)
	}

	fmt.Printf("%s", str)
}

func (w *writer) After(syscallNum, arg1, arg2, arg3, arg4, arg5, arg6, retVal int) {

	str := ""

	switch syscallNum {
	case syscall.SYS_OPEN:
		// int open(const char *path, int oflag, ...)
		fd := retVal
		str += fmt.Sprintf(`%d`, fd)
		w.provider.PutFileDescriptor(fd, w.path)
	case syscall.SYS_READ:
		// ssize_t read(int fildes, void *buf, size_t nbyte)
		if retVal <= arg3 {
			buf := shortString(w.provider.ReadPtraceTextBuf(uintptr(arg2), retVal))
			str += fmt.Sprintf(`%d: %s`, retVal, buf)
		} else {
			str += fmt.Sprintf(`%d`, retVal)
		}
	case syscall.SYS_GETUID, syscall.SYS_GETEUID,
		syscall.SYS_LSEEK,
		syscall.SYS_WRITE,
		syscall.SYS_STAT:
		str += fmt.Sprintf(`%d`, retVal)
	}

	fmt.Printf("= %s\n", str)
}

func formatFileDesc(fd int, path string) string {
	if path != "" {
		return fmt.Sprintf(`%d<%s>`, fd, path)
	} else {
		return strconv.Itoa(fd)
	}
}

func shortString(buf string) interface{} {
	buf = fmt.Sprintf("%q", buf)
	if len(buf) > 40 {
		buf = buf[0:18] + `"..."` + buf[len(buf)-19:]
	}
	return buf
}
