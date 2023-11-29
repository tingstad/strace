package main

import (
	"bytes"
	"testing"
)

const expected = `package syscalls

func init() {
	syscallNames[3] = "READ"
	syscallNames[5] = "OPEN"
}
`

func Test(t *testing.T) {
	var buf bytes.Buffer
	syscallNames := map[int]string{
		3: "READ",
		5: "OPEN",
	}

	write(&buf, syscallNames)

	if actual := buf.String(); actual != expected {
		t.Errorf("expected:\n%s\nbut got:\n%s\n", expected, actual)
	}
}
