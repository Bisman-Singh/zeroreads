// Package templating runs the OpenTelemetry Collector contrib drain processor in-process, so
// offline analysis derives templates with exactly the code, masking and defaults the pipeline
// uses. It never reimplements Drain.
package templating

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"

	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/drainprocessor"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/processor/processortest"
)

// DrainModule is the module path of the embedded processor. Only one version of it can be
// linked into a binary, so a CLI release is tied to one contrib version.
const DrainModule = "github.com/open-telemetry/opentelemetry-collector-contrib/processor/drainprocessor"

// Config is the drain processor's own configuration type, used unchanged.
type Config = drainprocessor.Config

// MaskRule is the drain processor's masking rule type, used unchanged.
type MaskRule = drainprocessor.MaskingRule

// DefaultConfig returns the drain processor's defaults, exactly as its factory creates them.
func DefaultConfig() *Config {
	return drainprocessor.NewFactory().CreateDefaultConfig().(*Config)
}

// Input is one log record to template. For structured records set Fields and leave Body empty;
// the processor's BodyField setting then selects the templated field.
type Input struct {
	Body   string
	Fields map[string]any
}

// Engine wraps one running drain processor instance. Its parse tree persists across calls, as it
// does in a long-running collector. It is not safe for concurrent use.
type Engine struct {
	cfg  *Config
	proc processor.Logs
	sink *consumertest.LogsSink
}

// New validates cfg and starts a drain processor with it.
func New(ctx context.Context, cfg *Config) (*Engine, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("drain config: %w", err)
	}
	f := drainprocessor.NewFactory()
	sink := new(consumertest.LogsSink)
	proc, err := f.CreateLogs(ctx, processortest.NewNopSettings(f.Type()), cfg, sink)
	if err != nil {
		return nil, err
	}
	if err := proc.Start(ctx, componenttest.NewNopHost()); err != nil {
		return nil, err
	}
	return &Engine{cfg: cfg, proc: proc, sink: sink}, nil
}

// Close shuts the processor down.
func (e *Engine) Close(ctx context.Context) error { return e.proc.Shutdown(ctx) }

// Template feeds the records through the processor in order, as one batch, and returns the
// template it wrote for each record ("" when it wrote none, for example during warmup).
func (e *Engine) Template(ctx context.Context, in []Input) ([]string, error) {
	ld := plog.NewLogs()
	lrs := ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords()
	for _, r := range in {
		lr := lrs.AppendEmpty()
		if r.Fields != nil {
			if err := lr.Body().SetEmptyMap().FromRaw(r.Fields); err != nil {
				return nil, err
			}
			continue
		}
		lr.Body().SetStr(r.Body)
	}
	e.sink.Reset()
	if err := e.proc.ConsumeLogs(ctx, ld); err != nil {
		return nil, err
	}
	got := e.sink.AllLogs()
	if len(got) != 1 {
		return nil, fmt.Errorf("processor emitted %d batches, want 1", len(got))
	}
	out := make([]string, 0, len(in))
	olrs := got[0].ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	if olrs.Len() != len(in) {
		return nil, fmt.Errorf("processor emitted %d records, want %d", olrs.Len(), len(in))
	}
	for i := 0; i < olrs.Len(); i++ {
		v, ok := olrs.At(i).Attributes().Get(e.cfg.TemplateAttribute)
		if !ok {
			out = append(out, "")
			continue
		}
		if v.Type() != pcommon.ValueTypeStr {
			return nil, errors.New("template attribute is not a string")
		}
		out = append(out, v.Str())
	}
	return out, nil
}

// DrainVersion reports the contrib version of the embedded drain processor, read from the
// binary's build info. Rules record it so a version change invalidates them.
func DrainVersion() (string, error) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "", errors.New("no build info")
	}
	for _, m := range bi.Deps {
		if m.Path == DrainModule {
			if m.Replace != nil {
				return m.Replace.Version, nil
			}
			return m.Version, nil
		}
	}
	return "", errors.New("drain processor not found in build info")
}
