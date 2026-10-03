package metrics

import (
	"strings"
	"testing"
)

func TestWriteText(t *testing.T) {
	c := NewCounter("t_calls_total", "Calls.\nTwo lines.", "action", "effect")
	c.Inc("tools.call", "allow")
	c.Inc("tools.call", "allow")
	c.Inc("tools.call", `de"ny`)
	h := NewHistogram("t_duration_seconds", "Duration.", []float64{.01, .1}, "query")
	h.Observe(.005, "q")
	h.Observe(.01, "q") // on a bound: in that bucket
	h.Observe(.5, "q")
	g := NewGauge("t_build_info", "Build.", func() float64 { return 1 }, "version", "0.4.0")
	r := &Registry{}
	r.Register(c, h, g)
	var b strings.Builder
	if err := r.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	want := `# HELP t_calls_total Calls.\nTwo lines.
# TYPE t_calls_total counter
t_calls_total{action="tools.call",effect="allow"} 2
t_calls_total{action="tools.call",effect="de\"ny"} 1
# HELP t_duration_seconds Duration.
# TYPE t_duration_seconds histogram
t_duration_seconds_bucket{query="q",le="0.01"} 2
t_duration_seconds_bucket{query="q",le="0.1"} 2
t_duration_seconds_bucket{query="q",le="+Inf"} 3
t_duration_seconds_sum{query="q"} 0.515
t_duration_seconds_count{query="q"} 3
# HELP t_build_info Build.
# TYPE t_build_info gauge
t_build_info{version="0.4.0"} 1
`
	if b.String() != want {
		t.Errorf("got\n%s\nwant\n%s", b.String(), want)
	}
	if v := c.Value("tools.call", "allow"); v != 2 {
		t.Errorf("Value = %v", v)
	}
}

// The gateway's metrics are all registered, and unlabelled families
// without values write only their header.
func TestDefault(t *testing.T) {
	var b strings.Builder
	if err := Default.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"mcp_gateway_decisions_total", "mcp_gateway_policy_failures_total",
		"mcp_gateway_opa_query_duration_seconds", "mcp_gateway_opa_query_errors_total", "mcp_gateway_instance_starts_total",
		"mcp_gateway_instance_failures_total", "mcp_gateway_approvals_decided_total", "mcp_gateway_limit_refusals_total"} {
		if !strings.Contains(b.String(), "# TYPE "+name+" ") {
			t.Errorf("%s missing", name)
		}
	}
}
