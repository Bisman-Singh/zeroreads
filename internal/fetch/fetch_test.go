package fetch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRetriesOnlyTransientReads(t *testing.T) {
	var calls atomic.Int32
	status := http.StatusServiceUnavailable
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(status)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	ctx := context.Background()
	send := func(method string) (Response, error) {
		calls.Store(0)
		req, _ := http.NewRequestWithContext(ctx, method, srv.URL, nil)
		return Do(ctx, srv.Client(), req)
	}
	if res, err := send(http.MethodGet); err != nil || string(res.Body) != "ok" || calls.Load() != 3 {
		t.Fatalf("GET after two 503s: %v %q, %d calls", err, res.Body, calls.Load())
	}
	if res, _ := send(http.MethodPost); res.Status != 503 || calls.Load() != 1 {
		t.Fatalf("POST is retried: %d calls", calls.Load())
	}
	status = http.StatusNotFound
	if res, _ := send(http.MethodGet); res.Status != 404 || calls.Load() != 1 {
		t.Fatalf("404 is retried: %d calls", calls.Load())
	}
	status = http.StatusTooManyRequests
	if res, err := send(http.MethodGet); err != nil || !res.OK() || calls.Load() != 3 {
		t.Fatalf("429: %v, %d calls", err, calls.Load())
	}
}

func TestGivesUpAfterAttempts(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	if res, err := Do(context.Background(), srv.Client(), req); err != nil || res.Status != 502 || calls.Load() != attempts {
		t.Fatalf("%v %d, %d calls", err, res.Status, calls.Load())
	}
}

func TestBoundsTheAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := []byte(strings.Repeat("x", 1<<20))
		for i := 0; i <= MaxBody>>20; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	if _, err := Do(context.Background(), srv.Client(), req); err != ErrTooLarge {
		t.Fatalf("got %v", err)
	}
}

func TestContextStopsRetries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable) // no Retry-After: backoff of 1s, then 4s
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	start := time.Now()
	if _, err := Do(ctx, srv.Client(), req); err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("%v after %v", err, time.Since(start))
	}
}

func TestRetryAfterAndExcerpt(t *testing.T) {
	for v, want := range map[string]time.Duration{"": -1, "3": 3 * time.Second, "9999": maxWait, "soon": -1} {
		if got := parseRetryAfter(v); got != want {
			t.Fatalf("%q: %v, want %v", v, got, want)
		}
	}
	long := strings.Repeat("é", 600)
	if e := Excerpt([]byte(long)); len(e) > 515 || !strings.HasSuffix(e, "...") || !strings.HasPrefix(e, "é") {
		t.Fatalf("excerpt %d bytes: %q", len(e), e[:20])
	}
	if e := Excerpt([]byte("  short\n")); e != "short" {
		t.Fatalf("%q", e)
	}
}
