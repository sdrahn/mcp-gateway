package policydata

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// yamlBlock is a fenced YAML block of the user guide.
var yamlBlock = regexp.MustCompile("(?s)```yaml\n(.*?)```")

// Every YAML example in the user guide reads as the gateway reads role
// data (ToJSON: no duplicate keys, no merge keys), and chapter 6's role
// data passes the schema but for the roles it leaves to the shipped
// default.
func TestUserGuideYAML(t *testing.T) {
	files, err := filepath.Glob("../../docs/user-guide/*.md")
	if err != nil || len(files) == 0 {
		t.Fatalf("user guide: %v", err)
	}
	n := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, m := range yamlBlock.FindAllSubmatch(b, -1) {
			n++
			data, err := ToJSON(m[1])
			if err != nil {
				t.Errorf("%s, YAML block %d: %v\n%s", filepath.Base(f), i+1, err, m[1])
				continue
			}
			if filepath.Base(f) == "06-policy.md" && i == 0 {
				problems, err := Check(data)
				if err != nil {
					t.Fatal(err)
				}
				for _, p := range problems {
					if !strings.Contains(p, `unknown role "admin"`) && !strings.Contains(p, `unknown role "dba"`) {
						t.Errorf("chapter 6's role data: %s", p)
					}
				}
			}
		}
	}
	if n < 10 {
		t.Errorf("%d YAML blocks", n)
	}
}
