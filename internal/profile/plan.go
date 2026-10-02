package profile

import (
	"encoding/json"
	"fmt"

	"github.com/sdrahn/mcp-gateway/internal/inspect"
)

// Call is a planned tool call.
type Call struct {
	Tool string         `json:"tool"`
	Args map[string]any `json:"args"`
	// Given: the arguments come from the calls file, not from the schema.
	Given bool `json:"given,omitempty"`
}

// ParseCalls reads a calls file: an object mapping tool names to an
// arguments object, or to a list of them for several calls.
func ParseCalls(data []byte) (map[string][]map[string]any, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	out := map[string][]map[string]any{}
	for tool, v := range raw {
		var one map[string]any
		if json.Unmarshal(v, &one) == nil && one != nil {
			out[tool] = []map[string]any{one}
			continue
		}
		var many []map[string]any
		if err := json.Unmarshal(v, &many); err != nil {
			return nil, fmt.Errorf("%s: want an arguments object or a list of them", tool)
		}
		out[tool] = many
	}
	return out, nil
}

// Plan lists the calls to make: the calls file's for the tools it names;
// for the others, one call with sample arguments for each reading tool,
// or for every tool with all (only on a system that may be changed).
// Tools of the calls file that the server does not have are returned as
// unknown.
func Plan(tools []inspect.Tool, verdicts []inspect.Verdict, given map[string][]map[string]any, all bool) (calls []Call, unknown []string) {
	have := map[string]bool{}
	for i, t := range tools {
		have[t.Name] = true
		if args, ok := given[t.Name]; ok {
			for _, a := range args {
				calls = append(calls, Call{Tool: t.Name, Args: a, Given: true})
			}
			continue
		}
		if all || verdicts[i].Class == inspect.ClassRead {
			calls = append(calls, Call{Tool: t.Name, Args: SampleArgs(t.InputSchema)})
		}
	}
	for _, name := range sortedKeys(given) {
		if !have[name] {
			unknown = append(unknown, name)
		}
	}
	return calls, unknown
}
