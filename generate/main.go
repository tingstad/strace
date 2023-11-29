package main

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"log"
	"os"
	"slices"
	"strconv"
	"strings"
)

func main() {
	syscallNames := getSyscalls()
	filename := "generated.go"
	file, err := os.Create(filename)
	if err != nil {
		log.Fatal(fmt.Errorf(`creating file "%s": %w`, filename, err))
	}
	write(file, syscallNames)
}

func write(writer io.Writer, syscallNames map[int]string) {
	fmt.Fprintf(writer, "package syscalls\n\nfunc init() {\n")

	keys := make([]int, 0, len(syscallNames))
	for key := range syscallNames {
		keys = append(keys, key)
	}
	slices.Sort(keys)

	for _, num := range keys {
		name := syscallNames[num]
		fmt.Fprintf(writer, "\tsyscallNames[%d] = \"%s\"\n", num, name)
	}
	fmt.Fprintf(writer, "}\n")
}

func getSyscalls() map[int]string {
	src := `package main
		import "syscall"
		
		const foo = syscall.SYS_WRITE`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "src.go", src, 0)
	if err != nil {
		log.Fatal(err) // parse error
	}
	conf := types.Config{Importer: importer.Default()}
	pkg, err := conf.Check("a/path", fset, []*ast.File{f}, nil)
	if err != nil {
		log.Fatal(err) // type error
	}
	scope := pkg.Imports()[0].Scope() // "syscall" import
	var syscallNames = map[int]string{}
	for _, name := range scope.Names() {
		if !strings.HasPrefix(name, "SYS_") {
			continue
		}
		obj := scope.Lookup(name)
		if c, ok := obj.(*types.Const); ok {
			str := c.Val().String()
			i, err := strconv.Atoi(str)
			if err != nil {
				log.Printf("WARNING: %v", fmt.Errorf(
					`converting "%s" (%s) to int: %w`, str, name, err))
				continue
			}
			syscallNames[i] = strings.TrimPrefix(name, "SYS_")
		}
	}
	return syscallNames
}
