// Package topology reads an OpenTelemetry Collector configuration and answers where logs go after
// a given point: every exporter a removed line would have reached, including through connectors,
// and every connector that turns logs into another signal (whose output a removal changes).
package topology

import (
	"fmt"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Config is a merged collector configuration.
type Config struct {
	Receivers  map[string]any
	Processors map[string]any
	Exporters  map[string]any
	Connectors map[string]any
	Pipelines  map[string]Pipeline
}

// Pipeline is one service pipeline.
type Pipeline struct {
	ID         string // e.g. logs, logs/app
	Signal     string // logs, metrics, traces, profiles
	Receivers  []string
	Processors []string
	Exporters  []string
}

// Load merges configuration files the way the collector does for repeated --config flags: maps are
// merged deeply, later files win, and lists are replaced, not appended.
func Load(files ...[]byte) (*Config, error) {
	merged := map[string]any{}
	for i, f := range files {
		var m map[string]any
		if err := yaml.Unmarshal(f, &m); err != nil {
			return nil, fmt.Errorf("topology: file %d: %w", i, err)
		}
		merged = mergeMaps(merged, m)
	}
	c := &Config{
		Receivers:  asMap(merged["receivers"]),
		Processors: asMap(merged["processors"]),
		Exporters:  asMap(merged["exporters"]),
		Connectors: asMap(merged["connectors"]),
		Pipelines:  map[string]Pipeline{},
	}
	service := asMap(merged["service"])
	for id, raw := range asMap(service["pipelines"]) {
		pm := asMap(raw)
		p := Pipeline{ID: id, Signal: strings.SplitN(id, "/", 2)[0]}
		var err error
		if p.Receivers, err = stringList(pm["receivers"]); err != nil {
			return nil, fmt.Errorf("topology: pipeline %s receivers: %w", id, err)
		}
		if p.Processors, err = stringList(pm["processors"]); err != nil {
			return nil, fmt.Errorf("topology: pipeline %s processors: %w", id, err)
		}
		if p.Exporters, err = stringList(pm["exporters"]); err != nil {
			return nil, fmt.Errorf("topology: pipeline %s exporters: %w", id, err)
		}
		c.Pipelines[id] = p
	}
	if err := c.check(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) check() error {
	for id, p := range c.Pipelines {
		for _, r := range p.Receivers {
			if _, ok := c.Receivers[r]; !ok {
				if _, ok := c.Connectors[r]; !ok {
					return fmt.Errorf("topology: pipeline %s uses undefined receiver %s", id, r)
				}
			}
		}
		for _, x := range p.Processors {
			if _, ok := c.Processors[x]; !ok {
				return fmt.Errorf("topology: pipeline %s uses undefined processor %s", id, x)
			}
		}
		for _, e := range p.Exporters {
			if _, ok := c.Exporters[e]; !ok {
				if _, ok := c.Connectors[e]; !ok {
					return fmt.Errorf("topology: pipeline %s uses undefined exporter %s", id, e)
				}
			}
		}
	}
	return nil
}

func mergeMaps(dst, src map[string]any) map[string]any {
	for k, v := range src {
		if sm, ok := v.(map[string]any); ok {
			if dm, ok := dst[k].(map[string]any); ok {
				dst[k] = mergeMaps(dm, sm)
				continue
			}
		}
		dst[k] = v
	}
	return dst
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}

func stringList(v any) ([]string, error) {
	if v == nil {
		return nil, nil
	}
	l, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("not a list")
	}
	out := make([]string, 0, len(l))
	for _, x := range l {
		s, ok := x.(string)
		if !ok {
			return nil, fmt.Errorf("entry %v is not a string", x)
		}
		out = append(out, s)
	}
	return out, nil
}

// Type returns a component's type: the part of its ID before the first "/".
func Type(id string) string { return strings.SplitN(id, "/", 2)[0] }

// Reach is everything a line leaving a point in a pipeline can reach.
type Reach struct {
	// Exporters that receive the lines (or data derived from them), with the path that leads there.
	Exporters map[string][]string
	// Derived lists connectors that turn logs into another signal. A removal changes their output,
	// so each is a counting consumer.
	Derived []string
	// Pipelines visited.
	Pipelines []string
}

// Downstream returns what lines reach from processor index after in pipeline (-1: straight after the
// receivers). Processors do not route, so every point of a pipeline reaches the same exporters: the
// index only has to exist. Connectors are followed into every pipeline that uses them as a receiver.
func (c *Config) Downstream(pipeline string, after int) (Reach, error) {
	p, ok := c.Pipelines[pipeline]
	if !ok {
		return Reach{}, fmt.Errorf("topology: no pipeline %s", pipeline)
	}
	if after < -1 || after >= len(p.Processors) {
		return Reach{}, fmt.Errorf("topology: pipeline %s has no processor index %d", pipeline, after)
	}
	r := Reach{Exporters: map[string][]string{}}
	seen := map[string]bool{}
	var walk func(pid string, path []string)
	walk = func(pid string, path []string) {
		if seen[pid] {
			return
		}
		seen[pid] = true
		r.Pipelines = append(r.Pipelines, pid)
		pp := c.Pipelines[pid]
		for _, e := range pp.Exporters {
			here := append(append([]string(nil), path...), pid+"->"+e)
			if _, isConn := c.Connectors[e]; isConn {
				for qid, q := range c.Pipelines {
					for _, rcv := range q.Receivers {
						if rcv != e {
							continue
						}
						if q.Signal != pp.Signal && !contains(r.Derived, e) {
							r.Derived = append(r.Derived, e)
						}
						walk(qid, here)
					}
				}
				continue
			}
			if _, dup := r.Exporters[e]; !dup {
				r.Exporters[e] = here
			}
		}
	}
	walk(pipeline, nil)
	sort.Strings(r.Derived)
	sort.Strings(r.Pipelines)
	return r, nil
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// SinkKind classifies an exporter by type.
func SinkKind(exporterID string) string {
	switch Type(exporterID) {
	case "otlp", "otlp_grpc", "otlphttp", "otlp_http":
		return "otlp" // Loki's OTLP endpoint, another collector, or a vendor: must be mapped explicitly
	case "loki", "lokiexporter":
		return "loki"
	case "debug", "logging", "nop":
		return "local" // writes to the collector's own output or nowhere
	}
	return "other"
}
