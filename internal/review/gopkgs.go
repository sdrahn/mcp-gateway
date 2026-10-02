package review

import (
	"bufio"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// GoPackageDirs returns the directories (relative to dir, the module root)
// of the module's own packages that the main package in mainRel imports,
// directly or not, including mainRel itself. Only the module's own
// packages are followed (by their import paths under the module path of
// go.mod); test files are left out.
func GoPackageDirs(dir, mainRel string) (map[string]bool, error) {
	module, err := modulePath(filepath.Join(dir, "go.mod"))
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	queue := []string{filepath.Clean(mainRel)}
	for len(queue) > 0 {
		rel := queue[0]
		queue = queue[1:]
		if seen[rel] {
			continue
		}
		seen[rel] = true
		imports, err := packageImports(filepath.Join(dir, rel))
		if err != nil {
			return nil, err
		}
		for _, imp := range imports {
			if imp == module {
				queue = append(queue, ".")
			} else if strings.HasPrefix(imp, module+"/") {
				queue = append(queue, filepath.FromSlash(strings.TrimPrefix(imp, module+"/")))
			}
		}
	}
	return seen, nil
}

func modulePath(gomod string) (string, error) {
	f, err := os.Open(gomod)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if fields := strings.Fields(sc.Text()); len(fields) == 2 && fields[0] == "module" {
			return strings.Trim(fields[1], `"`), nil
		}
	}
	return "", fmt.Errorf("%s: no module line", gomod)
}

// packageImports returns the imports of the non-test Go files in dir.
func packageImports(dir string) ([]string, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%s: no Go files", dir)
	}
	var out []string
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			return nil, err
		}
		for _, imp := range file.Imports {
			if p, err := strconv.Unquote(imp.Path.Value); err == nil {
				out = append(out, p)
			}
		}
	}
	return out, nil
}
