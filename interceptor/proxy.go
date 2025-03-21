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

// Proxy proxies `read` from a given file to HTTP Range requests
func Proxy(filename, url string, provider Provider) Interceptor {
	stderr := os.Stderr
	p := proxy{
		filename:   filename,
		url:        url,
		size:       -1,
		httpClient: http.Client{Timeout: 5 * time.Second},
		enabled:    filename != "" && url != "",
		provider:   provider,
		stderr:     stderr,
	}
	if p.enabled {
		p.createFile()
		p.getSize()
	}
	return &p
}

type proxy struct {
	filename     string
	url          string
	httpClient   http.Client
	size         int64
	cursor       int64
	date         string
	lastModified string
	contentType  string
	file         *os.File
	enabled      bool
	interceptors map[int]func()
	provider     Provider
	stderr       *os.File
	isTTY        bool
}

func (p *proxy) After(syscallNum, arg1, arg2, arg3, arg4, arg5, arg6, retVal int) {
}

func (p *proxy) Before(syscallNum, arg1, arg2, arg3, arg4, arg5, arg6 int) {
	if !p.enabled {
		return
	}

	switch syscallNum {
	case syscall.SYS_LSEEK:
		// off_t lseek(int fildes, off_t offset, int whence)
		if p.filename == p.provider.FileName(arg1) {
			oldOffset := p.cursor
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
			p.cursor = newOffset
		}
	case syscall.SYS_READ:
		// ssize_t read(int fildes, void *buf, size_t nbyte)
		if arg1 == p.provider.FileDescriptor(p.filename) {
			buf, err := p.read(arg1, arg3)
			if err != nil {
				panic(fmt.Sprintf("read: %v", err))
			}
			n := len(buf)
			if n < 1 {
				panic(fmt.Sprintf("no data from read: %d", n))
			}
			if n < arg3 {
				panic(fmt.Sprintf("got %d bytes but wanted %d", n, arg3))
			}
			written, err := p.file.WriteAt(buf, p.cursor)
			if err != nil {
				panic(fmt.Sprintf("file write: %v", err))
			}
			if written < n {
				panic(fmt.Sprintf("file write %d < %d", written, n))
			}
			p.cursor += int64(n)
		}
	}
}

func (p *proxy) getSize() int64 {
	if p.size == -1 {
		p.fetchSize()
	}
	return p.size
}

func (p *proxy) fetchSize() {
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
		p.size = int64(size)
	}
	if ranges := resp.Header.Get("accept-ranges"); !strings.Contains(ranges, "bytes") {
		panic(fmt.Sprintf(`accept-ranges "%s" does not accept bytes`, ranges))
	}
	p.contentType = resp.Header.Get("content-type")
	p.date = resp.Header.Get("date")
	p.lastModified = resp.Header.Get("last-modified")

	b := make([]byte, p.size)
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
	_, _ = p.stderr.WriteString(fmt.Sprintf("\n%s\n", strings.Join(lines, "\n")))

	_, _ = p.stderr.WriteString(fmt.Sprintf("wrote bytes: %d\n", n))
}

func (p *proxy) read(fd int, n int) ([]byte, error) {
	if fd != p.provider.FileDescriptor(p.filename) {
		return []byte{}, nil
	}

	req, err := http.NewRequest(http.MethodGet, p.url, nil)
	if err != nil {
		panic(fmt.Sprintf("http.NewRequest failed: %v", err))
	}
	if start, size := p.cursor, p.size; start > p.size {
		panic(fmt.Sprintf("range start %d larger than size %d", start, size))
	}
	end := p.cursor + int64(n)
	if size := p.size; end > p.size {
		panic(fmt.Sprintf("range end %d larger than size %d", end, size))
	}
	rangeHeader := fmt.Sprintf("bytes=%d-%d", p.cursor, end)
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
	_, _ = p.stderr.WriteString(fmt.Sprintf("\n%s\n", strings.Join(lines, "\n")))

	if statusCode := resp.StatusCode; statusCode >= 300 {
		panic(fmt.Sprintf("GET returned status code %d", statusCode))
	}

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(fmt.Sprintf("reading body: %v", err))
	}

	return buf, nil
}

func (p *proxy) createFile() {
	file, err := os.Create(p.filename)
	if err != nil {
		panic(fmt.Sprintf(`creating file "%s": %v`, p.filename, err))
	}
	p.file = file
}
