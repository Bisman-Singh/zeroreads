package fetch

import (
	"context"
	"errors"
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

// A read follows a redirect on its own server only; a redirect to another port or host, or of a write,
// is refused before anything reaches the other end.
func TestRedirectsStayOnTheConfiguredServer(t *testing.T) {
	var elsewhere atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer other.Close()
	var writes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/moved":
			http.Redirect(w, r, "/here", http.StatusFound)
		case "/away":
			http.Redirect(w, r, other.URL+"/steal", http.StatusFound)
		case "/write":
			if r.Method != http.MethodGet {
				writes.Add(1)
			}
			http.Redirect(w, r, "/here", http.StatusMovedPermanently)
		case "/here":
			if r.Method == http.MethodGet && r.Header.Get("Authorization") != "" {
				_, _ = w.Write([]byte("ok"))
			}
		}
	}))
	defer srv.Close()
	get := func(path, method string) (Response, error) {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader("x"))
		req.Header.Set("Authorization", "Bearer secret")
		return Do(context.Background(), srv.Client(), req)
	}
	if res, err := get("/moved", http.MethodGet); err != nil || string(res.Body) != "ok" {
		t.Fatalf("a redirect on the same server was not followed: %v %q", err, res.Body)
	}
	if _, err := get("/away", http.MethodGet); !errors.Is(err, ErrRedirect) || elsewhere.Load() != 0 {
		t.Fatalf("a redirect to another server was followed: %v, %d requests there", err, elsewhere.Load())
	}
	if _, err := get("/write", http.MethodPut); !errors.Is(err, ErrRedirect) || writes.Load() != 1 {
		t.Fatalf("a redirected write was not refused: %v", err)
	}
}
