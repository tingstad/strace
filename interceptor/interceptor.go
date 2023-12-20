package interceptor

type Interceptor interface {
	Before(syscallNum, arg1, arg2, arg3, arg4, arg5, arg6 int)
	After(syscallNum, arg1, arg2, arg3, arg4, arg5, arg6, retVal int)
}

type Provider interface {
	ReadPtraceText(addr uintptr) string
	ReadPtraceTextBuf(addr uintptr, size int) string
	FileDescriptor(filename string) int
	FileName(fd int) string
	PutFileDescriptor(fd int, path string)
}
