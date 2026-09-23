package pricing

import "testing"

func TestMonthly(t *testing.T) {
	a, _ := Lookup("example-a")
	if got := a.Monthly(10*GB, 0); got != 300 {
		t.Fatalf("example-a: %v", got)
	}
	c, _ := Lookup("example-c")
	if got := c.Monthly(1*GB, 1e6); got != 30*(0.20+2.00) {
		t.Fatalf("example-c: %v", got)
	}
	none, _ := Lookup("")
	if got := none.Monthly(1e12, 1e9); got != 0 {
		t.Fatalf("none: %v", got)
	}
	if _, err := Lookup("example-z"); err == nil {
		t.Fatal("unknown backend accepted")
	}
}
