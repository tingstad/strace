package interceptor

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Proxy struct {
	Filename     string
	url          string
	httpClient   http.Client
	Size         int64
	Cursor       int64
	Date         string
	LastModified string
	ContentType  string
	file         *os.File
	enabled      bool
	interceptors map[int]func()
	provider     Provider
}

type Provider interface {
	ReadPtraceText(addr uintptr) string
	FileDescriptor(filename string) int
	FileName(fd int) string
}

func New(filename, url string, provider Provider) *Proxy {
	p := Proxy{
		Filename:   filename,
		url:        url,
		Size:       -1,
		httpClient: http.Client{Timeout: 5 * time.Second},
		enabled:    filename != "" && url != "",
		provider:   provider,
	}
	if p.enabled {
		p.open()
		p.getSize()
	}
	return &p
}

func (p *Proxy) After(syscallNum, arg1, arg2, arg3, arg4, arg5, arg6, retVal int) {
}
func (p *Proxy) Before(syscallNum, arg1, arg2, arg3, arg4, arg5, arg6 int) {
	if !p.enabled {
		return
	}

	switch syscallNum {
	case syscall.SYS_LSEEK:
		// off_t lseek(int fildes, off_t offset, int whence)
		if p.Filename == p.provider.FileName(arg1) {
			oldOffset := p.Cursor
			newOffset := int64(-1)
			// If whence is SEEK_SET, the file offset shall be set to offset bytes.
			// If whence is SEEK_CUR, the file offset shall be set to its current location plus offset.
			// If whence is SEEK_END, the file offset shall be set to the size of the file plus offset.
			// https://pubs.opengroup.org/onlinepubs/009696799/functions/lseek.html
			switch offset, whence := int64(arg2), arg3; whence {
			case 0: // SEEK_SET
				newOffset = offset
			case 1: // SEEK_CUR
				newOffset = oldOffset + offset
			case 2: // SEEK_END
				newOffset = p.getSize() + offset
			default:
				panic(fmt.Sprintf("LSEEK whence/arg3 unexpected value: %d", whence))
			}
			p.Cursor = newOffset
		}
	case syscall.SYS_READ:
		// ssize_t read(int fildes, void *buf, size_t nbyte)
		if arg1 == p.provider.FileDescriptor(p.Filename) {
			buf, err := p.Read(arg1, arg3)
			if err != nil {
				panic(fmt.Sprintf("Read: %v", err))
			}
			n := len(buf)
			if n < 1 {
				panic(fmt.Sprintf("no data from Read: %d", n))
			}
			if n < arg3 {
				panic(fmt.Sprintf("got %d bytes but wanted %d", n, arg3))
			}
			written, err := p.file.WriteAt(buf, p.Cursor)
			if err != nil {
				panic(fmt.Sprintf("file write: %v", err))
			}
			if written < n {
				panic(fmt.Sprintf("file write %d < %d", written, n))
			}
			p.Cursor += int64(n)
		}
	}
}

func (p *Proxy) getSize() int64 {
	if p.Size == -1 {
		p.fetchSize()
	}
	return p.Size
}

func (p *Proxy) fetchSize() {
	resp, err := p.httpClient.Head(p.url)
	if err != nil {
		panic(fmt.Sprintf("HTTP HEAD failed: %v", err))
	}
	if statusCode := resp.StatusCode; statusCode != http.StatusOK {
		panic(fmt.Sprintf("HEAD returned status code %d", statusCode))
	}
	length := resp.Header.Get("content-length")
	if size, err := strconv.Atoi(length); err != nil {
		panic(fmt.Sprintf(`invalid content-length "%s": %v`, length, err))
	} else {
		p.Size = int64(size)
	}
	if ranges := resp.Header.Get("accept-ranges"); !strings.Contains(ranges, "bytes") {
		panic(fmt.Sprintf(`accept-ranges "%s" does not accept bytes`, ranges))
	}
	p.ContentType = resp.Header.Get("content-type")
	p.Date = resp.Header.Get("date")
	p.LastModified = resp.Header.Get("last-modified")

	b := make([]byte, p.Size)
	n, err := p.file.Write(b)
	if err != nil {
		panic(fmt.Sprintf(`writing to new file: %v`, err))
	}

	lines := []string{}
	lines = append(lines, fmt.Sprintf("> HEAD %s", p.url))
	lines = append(lines, "")
	lines = append(lines, fmt.Sprintf("< %s %s", resp.Proto, resp.Status))
	for _, name := range []string{"content-type", "content-length", "accept-ranges", "last-modified", "date"} {
		if value := resp.Header.Get(name); value != "" {
			lines = append(lines, fmt.Sprintf("< %s: %s", name, value))
		}
	}
	fmt.Println(fmt.Sprintf("\n%s\n", strings.Join(lines, "\n")))

	fmt.Println("wrote bytes: ", n)
}

func (p *Proxy) Read(fd int, n int) ([]byte, error) {
	if fd != p.provider.FileDescriptor(p.Filename) {
		return []byte{}, nil
	}

	req, err := http.NewRequest(http.MethodGet, p.url, nil)
	if err != nil {
		panic(fmt.Sprintf("http.NewRequest failed: %v", err))
	}
	if start, size := p.Cursor, p.Size; start > p.Size {
		panic(fmt.Sprintf("range start %d larger than size %d", start, size))
	}
	end := p.Cursor + int64(n)
	if size := p.Size; end > p.Size {
		panic(fmt.Sprintf("range end %d larger than size %d", end, size))
	}
	rangeHeader := fmt.Sprintf("bytes=%d-%d", p.Cursor, end)
	req.Header.Set("Range", rangeHeader)
	resp, err := p.httpClient.Do(req)
	if err != nil {
		panic(fmt.Sprintf("HTTP GET failed: %v", err))
	}
	defer resp.Body.Close()

	lines := []string{}
	lines = append(lines, fmt.Sprintf("> GET %s", p.url))
	lines = append(lines, fmt.Sprintf("> Range: %s", rangeHeader))
	lines = append(lines, "")
	lines = append(lines, fmt.Sprintf("< %s %s", resp.Proto, resp.Status))
	for _, name := range []string{"content-length"} {
		if value := resp.Header.Get(name); value != "" {
			lines = append(lines, fmt.Sprintf("< %s: %s", name, value))
		}
	}
	fmt.Println(fmt.Sprintf("\n%s\n", strings.Join(lines, "\n")))

	if statusCode := resp.StatusCode; statusCode >= 300 {
		panic(fmt.Sprintf("GET returned status code %d", statusCode))
	}

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(fmt.Sprintf("reading body: %v", err))
	}

	return buf, nil
}

func (p *Proxy) open() {
	file, err := os.Create(p.Filename)
	if err != nil {
		panic(fmt.Sprintf(`creating file "%s": %v`, p.Filename, err))
	}
	p.file = file
}
