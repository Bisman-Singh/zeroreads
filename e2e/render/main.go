// Command render prints the collector config for the e2e pipeline. Seeds and the IP mask come
// from the ground-truth corpus, so the pipeline and the embedded engine are configured identically.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/Bisman-Singh/zeroreads/internal/gen"
)

const tmpl = `receivers:
  file_log:
    include: [/var/log/pods/%s_*/*/*.log]
    start_at: beginning
    include_file_path: true
    operators:
      - type: container
        id: container-parser

  file_log/loki:
    include: [/var/log/pods/zeroreads-system_%s_*/loki/*.log]
    start_at: beginning
    include_file_path: true
    operators:
      - type: container
        id: container-parser

processors:
  transform/service:
    error_mode: propagate
    log_statements:
      - context: resource
        statements:
          - set(resource.attributes["service.name"], resource.attributes["k8s.container.name"])
  transform/prep:
    error_mode: propagate
    log_statements:
      - context: resource
        statements:
          - set(resource.attributes["service.name"], resource.attributes["k8s.container.name"])
      - context: log
        statements:
          - set(log.attributes["service.name"], resource.attributes["k8s.container.name"])
          # Bytes are captured while the body is still the raw string line.
          - set(log.attributes["zeroreads.body_bytes"], Len(log.body))
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
      - name: zeroreads.template.records
        attributes: [{key: service.name}, {key: log.record.template}]
        sum:
          value: "1"
          monotonic: true
      - name: zeroreads.template.bytes
        attributes: [{key: service.name}, {key: log.record.template}]
        sum:
          value: log.attributes["zeroreads.body_bytes"]
          monotonic: true
      # Len(body) after JSON parsing, recorded to check what Len returns for a map body.
      - name: zeroreads.template.len_after_parse
        attributes: [{key: service.name}, {key: log.record.template}]
        sum:
          value: Len(log.body)
          monotonic: true

exporters:
  file/logs:
    path: /e2e/out/logs.json
  file/metrics:
    path: /e2e/out/metrics.json
  otlp_http/loki:
    endpoint: http://loki.zeroreads-system.svc:3100/otlp

service:
  telemetry:
    logs:
      level: info
  pipelines:
    logs:
      receivers: [file_log]
      processors: [transform/prep, drain]
      exporters: [file/logs, otlp_http/loki, signal_to_metrics]
    metrics:
      receivers: [signal_to_metrics]
      exporters: [file/metrics]
    logs/loki-self:
      receivers: [file_log/loki]
      processors: [transform/service]
      exporters: [otlp_http/loki]
`

// loop is the "user" collector config the full-loop test analyses, emits from and deploys: logs of
// every zeroreads-loop-* namespace go to Loki and a local file, and an independent pipeline keeps a
// raw copy of every record so removal can be checked line by line.
const loop = `receivers:
  file_log/loop:
    include: [/var/log/pods/zeroreads-loop-*_*/*/*.log]
    start_at: end
    include_file_path: true
    operators:
      - type: container
        id: container-parser
  file_log/loki:
    include: [/var/log/pods/zeroreads-system_loki-*/loki/*.log]
    start_at: end
    include_file_path: true
    operators:
      - type: container
        id: container-parser

processors:
  transform/service:
    error_mode: propagate
    log_statements:
      - context: resource
        statements:
          - set(resource.attributes["service.name"], resource.attributes["k8s.container.name"])
  transform/prep:
    error_mode: propagate
    log_statements:
      - context: resource
        statements:
          - set(resource.attributes["service.name"], resource.attributes["k8s.container.name"])
      - context: log
        statements:
          - set(log.body, ParseJSON(log.body)) where resource.attributes["k8s.container.name"] == "orders"

exporters:
  otlp_http/loki:
    endpoint: http://loki.zeroreads-system.svc:3100/otlp
  file/logs:
    path: /e2e/out/loop-logs.json
  file/raw:
    path: /e2e/out/loop-raw.json
  file/metrics:
    path: /e2e/out/loop-metrics.json

service:
  pipelines:
    logs:
      receivers: [file_log/loop]
      processors: [transform/prep]
      exporters: [otlp_http/loki, file/logs]
    logs/raw:
      receivers: [file_log/loop]
      processors: [transform/prep]
      exporters: [file/raw]
    logs/loki-self:
      receivers: [file_log/loki]
      processors: [transform/service]
      exporters: [otlp_http/loki]
`

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--loop" {
		fmt.Print(loop)
		return
	}
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: render <generator-namespace> <loki-pod> | render --loop")
		os.Exit(2)
	}
	var seeds []string
	for _, s := range gen.SeedTemplates() {
		seeds = append(seeds, "      - '"+strings.ReplaceAll(s, "'", "''")+"'")
	}
	if _, err := fmt.Fprintf(os.Stdout, tmpl, os.Args[1], os.Args[2], gen.IPMaskName, gen.IPMaskPattern, strings.Join(seeds, "\n")); err != nil {
		os.Exit(1)
	}
}
