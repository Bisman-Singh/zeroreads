// Package pricing turns removed volume into money for the backends whose prices were verified,
// with the date and source of each price. Self-hosted backends report volume only.
package pricing

import "fmt"

// Table is one backend's ingest price.
type Table struct {
	Backend      string
	PerGB        float64 // USD per GB removed before ingestion
	PerMillion   float64 // USD per million events removed (indexing), 0 if not billed per event
	AsOf, Source string
	Notes        string
}

// GB is 10^9 bytes, the unit these vendors bill in.
const GB = 1e9

var tables = map[string]Table{
	"none": {Backend: "none", Notes: "self-hosted or unknown backend: volume only"},
	"example-a": {Backend: "example-a", PerGB: 1.00, AsOf: "2026-09-23",
		Source: "illustrative", Notes: "billed per GB"},
	"example-b": {Backend: "example-b", PerGB: 0.80, AsOf: "2026-09-23",
		Source: "illustrative", Notes: "billed per GB"},
	"example-c": {Backend: "example-c", PerGB: 0.20, PerMillion: 2.00, AsOf: "2026-09-23",
		Source: "illustrative", Notes: "billed per GB and per million events"},
	"example-d": {Backend: "example-d", PerGB: 0.60, AsOf: "2026-09-23",
		Source: "illustrative", Notes: "billed per GB"},
}

// Lookup returns the table for a backend name.
func Lookup(backend string) (Table, error) {
	if backend == "" {
		backend = "none"
	}
	t, ok := tables[backend]
	if !ok {
		return Table{}, fmt.Errorf("pricing: unknown backend %q", backend)
	}
	return t, nil
}

// Monthly is the USD per 30-day month saved by removing bytesPerDay and linesPerDay.
func (t Table) Monthly(bytesPerDay, linesPerDay float64) float64 {
	return 30 * (bytesPerDay/GB*t.PerGB + linesPerDay/1e6*t.PerMillion)
}
