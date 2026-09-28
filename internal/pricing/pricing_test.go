package pricing

import "testing"

func TestMonthly(t *testing.T) {
	for _, c := range []struct {
		p           Price
		bytes, rows float64
		want        float64
	}{
		{Price{PerGB: 0.5}, 10 * GB, 0, 150},
		{Price{PerGB: 0.1, PerMillionLines: 1.7}, 1 * GB, 1e6, 30 * (0.1 + 1.7)},
		{Price{}, 1e12, 1e9, 0},
	} {
		if got := c.p.Monthly(c.bytes, c.rows); got != c.want {
			t.Fatalf("%+v: %v, want %v", c.p, got, c.want)
		}
	}
	if (Price{}).Set() || !(Price{PerMillionLines: 1}).Set() {
		t.Fatal("Set")
	}
}
