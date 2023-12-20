package interceptor

type writer struct {
}

func NewWriter() *writer {
	return &writer{}
}

func (w *writer) Before(syscallNum, arg1, arg2, arg3, arg4, arg5, arg6 int) {
}

func (w *writer) After(syscallNum, arg1, arg2, arg3, arg4, arg5, arg6, retVal int) {
}
