package proxy

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type Proxy struct {
	Filename     string
	url          string
	httpClient   http.Client
	Size         int64
	Cursor       int64
	Fd           int
	Date         string
	LastModified string
	ContentType  string
	file         *os.File
}

func New(filename, url string) *Proxy {
	return &Proxy{
		Filename:   filename,
		url:        url,
		Size:       -1,
		httpClient: http.Client{Timeout: 5 * time.Second},
	}
}

func (p *Proxy) GetSize() {
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

	n, err := p.file.WriteAt([]byte{0}, p.Size-1)
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

func (p *Proxy) Open() {
	file, err := os.Create(p.Filename)
	if err != nil {
		panic(fmt.Sprintf(`creating file "%s": %v`, p.Filename, err))
	}
	p.file = file
}
