// Package metrics counts what the gateway does and writes it in the
// Prometheus text format (version 0.0.4): policy decisions, OPA query
// latency, backend instance starts and failures, approvals. The gateway
// serves it on the control socket (GET /v1/metrics) and, if configured,
// on a plain HTTP listener (metrics.listen).
//
// See docs/architecture.md, section 11, step 13.
package metrics

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The gateway's metrics.
var (
	Decisions = NewCounter("mcp_gateway_decisions_total",
		"Policy decisions enforced, by action and effect (a call asked again after an approval counts twice).",
		"action", "effect")
	PolicyFailures = NewCounter("mcp_gateway_policy_failures_total",
		"Decisions that failed closed: OPA did not answer (error) or answered with an invalid decision (invalid).",
		"reason")
	OPADuration = NewHistogram("mcp_gateway_opa_query_duration_seconds",
		"Duration of queries to OPA, by query.",
		[]float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1}, "query")
	OPAErrors = NewCounter("mcp_gateway_opa_query_errors_total",
		"Queries to OPA that failed (unreachable, timeout, undefined or malformed result), by query.",
		"query")
	InstanceStarts = NewCounter("mcp_gateway_instance_starts_total",
		"Backend instances started, by server.",
		"server")
	InstanceFailures = NewCounter("mcp_gateway_instance_failures_total",
		"Backend instances that failed to start (stage start) or exited without being stopped (stage exit), by server.",
		"server", "stage")
	ApprovalsDecided = NewCounter("mcp_gateway_approvals_decided_total",
		"Approvals decided by a person, by decision (approve, deny).",
		"decision")
)

// Default holds the gateway's metrics.
var Default = &Registry{}

func init() {
	Default.Register(Decisions, PolicyFailures, OPADuration, OPAErrors, InstanceStarts, InstanceFailures, ApprovalsDecided)
}

// Metric is one metric family.
type Metric interface {
	write(w io.Writer) error
}

// Registry is a set of metric families.
type Registry struct {
	mu      sync.Mutex
	metrics []Metric
}

// Register adds metric families.
func (r *Registry) Register(ms ...Metric) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.metrics = append(r.metrics, ms...)
}

// ContentType is the media type of WriteText's output.
const ContentType = "text/plain; version=0.0.4; charset=utf-8"

// WriteText writes all metrics in the Prometheus text format.
func (r *Registry) WriteText(w io.Writer) error {
	r.mu.Lock()
	ms := append([]Metric(nil), r.metrics...)
	r.mu.Unlock()
	for _, m := range ms {
		if err := m.write(w); err != nil {
			return err
		}
	}
	return nil
}

// Counter is a counter family with labels.
type Counter struct {
	name, help string
	labels     []string
	mu         sync.Mutex
	values     map[string]float64 // by encoded label values
}

// NewCounter returns a counter family.
func NewCounter(name, help string, labels ...string) *Counter {
	return &Counter{name: name, help: help, labels: labels, values: map[string]float64{}}
}

// Inc adds one to the counter with these label values (one per label).
func (c *Counter) Inc(values ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.values[labelPairs(c.labels, values)]++
}

// Value returns the counter with these label values.
func (c *Counter) Value(values ...string) float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.values[labelPairs(c.labels, values)]
}

func (c *Counter) write(w io.Writer) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", c.name, escapeHelp(c.help), c.name); err != nil {
		return err
	}
	for _, k := range sortedKeys(c.values) {
		if _, err := fmt.Fprintf(w, "%s%s %s\n", c.name, braced(k), formatFloat(c.values[k])); err != nil {
			return err
		}
	}
	return nil
}

// Gauge is a gauge read from a function when the metrics are written.
type Gauge struct {
	name, help string
	labels     string // fixed label pairs, encoded
	value      func() float64
}

// NewGauge returns a gauge whose value comes from value; labels are fixed
// name, value pairs (e.g. the version of build_info).
func NewGauge(name, help string, value func() float64, labels ...string) *Gauge {
	var names, values []string
	for i := 0; i+1 < len(labels); i += 2 {
		names = append(names, labels[i])
		values = append(values, labels[i+1])
	}
	return &Gauge{name: name, help: help, labels: labelPairs(names, values), value: value}
}

func (g *Gauge) write(w io.Writer) error {
	_, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s%s %s\n",
		g.name, escapeHelp(g.help), g.name, g.name, braced(g.labels), formatFloat(g.value()))
	return err
}

// Histogram is a histogram family with labels.
type Histogram struct {
	name, help string
	labels     []string
	buckets    []float64 // upper bounds, ascending, without +Inf
	mu         sync.Mutex
	series     map[string]*histSeries
}

type histSeries struct {
	counts []uint64 // per bucket, not cumulative; last is +Inf
	sum    float64
	count  uint64
}

// NewHistogram returns a histogram family with these bucket bounds.
func NewHistogram(name, help string, buckets []float64, labels ...string) *Histogram {
	return &Histogram{name: name, help: help, labels: labels, buckets: buckets, series: map[string]*histSeries{}}
}

// Observe records a value for these label values.
func (h *Histogram) Observe(v float64, values ...string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	k := labelPairs(h.labels, values)
	s := h.series[k]
	if s == nil {
		s = &histSeries{counts: make([]uint64, len(h.buckets)+1)}
		h.series[k] = s
	}
	i := sort.SearchFloat64s(h.buckets, v) // first bound >= v
	s.counts[i]++
	s.sum += v
	s.count++
}

// Since records the time since start, in seconds.
func (h *Histogram) Since(start time.Time, values ...string) {
	h.Observe(time.Since(start).Seconds(), values...)
}

func (h *Histogram) write(w io.Writer) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", h.name, escapeHelp(h.help), h.name); err != nil {
		return err
	}
	for _, k := range sortedKeys(h.series) {
		s := h.series[k]
		var cum uint64
		for i, bound := range append(append([]float64(nil), h.buckets...), math.Inf(1)) {
			cum += s.counts[i]
			le := `le="` + formatFloat(bound) + `"`
			if k != "" {
				le = k + "," + le
			}
			if _, err := fmt.Fprintf(w, "%s_bucket{%s} %d\n", h.name, le, cum); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "%s_sum%s %s\n%s_count%s %d\n", h.name, braced(k), formatFloat(s.sum), h.name, braced(k), s.count); err != nil {
			return err
		}
	}
	return nil
}

// labelPairs encodes label names and values as `a="x",b="y"`. Missing
// values are empty.
func labelPairs(names, values []string) string {
	var b strings.Builder
	for i, n := range names {
		v := ""
		if i < len(values) {
			v = values[i]
		}
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(n + `="` + escapeValue(v) + `"`)
	}
	return b.String()
}

func braced(pairs string) string {
	if pairs == "" {
		return ""
	}
	return "{" + pairs + "}"
}

var (
	valueEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	helpEscaper  = strings.NewReplacer(`\`, `\\`, "\n", `\n`)
)

func escapeValue(s string) string { return valueEscaper.Replace(s) }
func escapeHelp(s string) string  { return helpEscaper.Replace(s) }

func formatFloat(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
