// Command render prints the collector config for the e2e pipeline. Seeds and the IP mask come
// from the ground-truth corpus, so the pipeline and the embedded engine are configured identically.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/Bisman-Singh/sievelog/internal/gen"
)

const tmpl = `receivers:
  file_log:
    include: [/var/log/pods/%s_*/*/*.log]
    start_at: beginning
    include_file_path: true
    operators:
      - type: container
        id: container-parser

processors:
  transform/prep:
    error_mode: propagate
    log_statements:
      - context: log
        statements:
          - set(log.attributes["service.name"], resource.attributes["k8s.container.name"])
          # Bytes are captured while the body is still the raw string line.
          - set(log.attributes["sievelog.body_bytes"], Len(log.body))
          - set(log.body, ParseJSON(log.body)) where resource.attributes["k8s.container.name"] == "orders"
  drain:
    body_field: msg
    masking_rules:
      - name: %s
        pattern: '%s'
    seed_templates:
%s

connectors:
  signal_to_metrics:
    logs:
      - name: sievelog.template.records
        attributes: [{key: service.name}, {key: log.record.template}]
        sum:
          value: "1"
          monotonic: true
      - name: sievelog.template.bytes
        attributes: [{key: service.name}, {key: log.record.template}]
        sum:
          value: log.attributes["sievelog.body_bytes"]
          monotonic: true
      # Len(body) after JSON parsing, recorded to check what Len returns for a map body.
      - name: sievelog.template.len_after_parse
        attributes: [{key: service.name}, {key: log.record.template}]
        sum:
          value: Len(log.body)
          monotonic: true

exporters:
  file/logs:
    path: /e2e/out/logs.json
  file/metrics:
    path: /e2e/out/metrics.json

service:
  telemetry:
    logs:
      level: info
  pipelines:
    logs:
      receivers: [file_log]
      processors: [transform/prep, drain]
      exporters: [file/logs, signal_to_metrics]
    metrics:
      receivers: [signal_to_metrics]
      exporters: [file/metrics]
`

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: render <generator-namespace>")
		os.Exit(2)
	}
	var seeds []string
	for _, s := range gen.SeedTemplates() {
		seeds = append(seeds, "      - '"+strings.ReplaceAll(s, "'", "''")+"'")
	}
	if _, err := fmt.Fprintf(os.Stdout, tmpl, os.Args[1], gen.IPMaskName, gen.IPMaskPattern, strings.Join(seeds, "\n")); err != nil {
		os.Exit(1)
	}
}
