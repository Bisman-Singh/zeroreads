package grafana

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A Grafana that always answers with another page cannot keep a read going: a repeated continue token
// ends a list, and every org's read has a request budget. Either way the read fails, as a gap.
func TestPagingStopsOnAServerThatNeverEnds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/apis/"):
			_, _ = w.Write([]byte(`{"items":[{}],"metadata":{"continue":"again"}}`))
		case r.URL.Path == "/api/library-elements":
			els := strings.Repeat(`{"uid":"x","model":{}},`, 99) + `{"uid":"x","model":{}}`
			_, _ = w.Write([]byte(`{"result":{"totalCount":1000000000,"elements":[` + els + `]}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := &Client{Base: srv.URL}
	r := &orgReader{c: c, org: 1, res: &Result{}}
	if _, err := r.listK8s(context.Background(), "dashboard.grafana.app", "v1", "dashboards"); err == nil || !strings.Contains(err.Error(), "continue token") {
		t.Fatalf("a repeated continue token was followed: %v", err)
	}
	r = &orgReader{c: c, org: 1, res: &Result{}, budget: 5}
	r.loadLibraries(context.Background())
	if len(r.res.Gaps) != 1 || !strings.Contains(r.res.Gaps[0].Reason, "stopped after 5 requests") || r.requests != 6 {
		t.Fatalf("pages without end were read: %d requests, gaps %+v", r.requests, r.res.Gaps)
	}
}
