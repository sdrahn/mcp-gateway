package main

import (
	"path"
	"strings"
)

// globMatch matches a slash-separated relative path against a glob
// pattern: "*", "?" and "[...]" within one path component (path.Match),
// "**" for any number of components. A pattern without a slash matches
// the last component, at any depth ("*.go" finds every Go file), as find
// -name does; agents use both forms.
func globMatch(pattern, name string) bool {
	if !strings.Contains(pattern, "/") {
		ok, _ := path.Match(pattern, path.Base(name))
		return ok
	}
	return matchParts(strings.Split(strings.Trim(pattern, "/"), "/"), strings.Split(name, "/"))
}

func matchParts(pat, name []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			for len(pat) > 1 && pat[1] == "**" {
				pat = pat[1:]
			}
			if len(pat) == 1 {
				return true
			}
			for i := 0; i <= len(name); i++ {
				if matchParts(pat[1:], name[i:]) {
					return true
				}
			}
			return false
		}
		if len(name) == 0 {
			return false
		}
		if ok, _ := path.Match(pat[0], name[0]); !ok {
			return false
		}
		pat, name = pat[1:], name[1:]
	}
	return len(name) == 0
}

// validGlob reports whether pattern is well formed.
func validGlob(pattern string) bool {
	for _, part := range strings.Split(pattern, "/") {
		if part == "**" {
			continue
		}
		if _, err := path.Match(part, ""); err != nil {
			return false
		}
	}
	return pattern != ""
}
