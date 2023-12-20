package interceptor

type Interceptor interface {
	Before(syscallNum, arg1, arg2, arg3, arg4, arg5, arg6 int)
	After(syscallNum, arg1, arg2, arg3, arg4, arg5, arg6, retVal int)
}
