// Package pricing turns removed volume into money at the operator's own prices. sievelog measures
// volume exactly, and only the operator knows what a gigabyte or a million lines costs them once
// region, plan, retention and discounts are applied, so no price is built in.
package pricing

// GB is 10^9 bytes, the unit log services bill in.
const GB = 1e9

// Price is what the operator pays per gigabyte ingested and per million lines (events) indexed, in
// Currency. Zero prices mean the report shows volume only.
type Price struct {
	PerGB           float64 `json:"per_gb,omitempty"`
	PerMillionLines float64 `json:"per_million_lines,omitempty"`
	Currency        string  `json:"currency,omitempty"`
}

// Set reports whether any price was given.
func (p Price) Set() bool { return p.PerGB > 0 || p.PerMillionLines > 0 }

// Monthly is the money saved per 30-day month by removing bytesPerDay and linesPerDay.
func (p Price) Monthly(bytesPerDay, linesPerDay float64) float64 {
	return 30 * (bytesPerDay/GB*p.PerGB + linesPerDay/1e6*p.PerMillionLines)
}
