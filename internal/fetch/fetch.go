// Package fetch sends the evidence sources' HTTP requests. An answer is read up to a size bound, so a
// misbehaving server cannot exhaust memory; a failed answer keeps only the start of its body, so
// reports stay readable; and a read (GET) that fails transiently is retried with backoff, so one
// blip does not turn days of evidence into a gap.
package fetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// MaxBody bounds one answer. A Loki page holding a single timestamp's lines can legitimately be
// large, so the bound only stops a server that answers without end.
const MaxBody = 512 << 20

// attempts is how often a transient failure of a read is tried in all, and maxWait the longest wait
// a Retry-After header is honoured for.
const (
	attempts = 4
	maxWait  = time.Minute
)

// ErrTooLarge means an answer exceeded MaxBody.
var ErrTooLarge = fmt.Errorf("fetch: answer larger than %d bytes", MaxBody)

// ErrRedirect means a redirect was refused.
var ErrRedirect = errors.New("fetch: redirect refused")

// Response is a completed exchange.
type Response struct {
	Status int
	Body   []byte
}

// OK reports a 2xx status.
func (r Response) OK() bool { return r.Status/100 == 2 }

// Do sends req with c and reads the answer. A GET is retried when the connection fails (not when it
// times out: a query that took too long will again) or the answer is 429, 502, 503 or 504. Other
// methods are sent once: they change state.
func Do(ctx context.Context, c *http.Client, req *http.Request) (Response, error) {
	guarded := *c
	guarded.CheckRedirect = redirect
	for attempt := 1; ; attempt++ {
		res, retryAfter, err := once(&guarded, req.Clone(ctx))
		if attempt == attempts || !transient(req.Method, res.Status, err) {
			return res, err
		}
		wait := time.Duration(1<<(2*(attempt-1))) * time.Second // 1s, 4s, 16s
		if retryAfter >= 0 {
			wait = retryAfter
		}
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		case <-time.After(wait):
		}
	}
}

// once sends one request. retryAfter is the server's Retry-After, or -1 when it gave none.
func once(c *http.Client, req *http.Request) (res Response, retryAfter time.Duration, err error) {
	resp, err := c.Do(req)
	if err != nil {
		return Response{}, -1, err
	}
	defer func() { _ = resp.Body.Close() }() // read to the end or to the bound; nothing is left to report
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
	if err != nil {
		return Response{Status: resp.StatusCode}, -1, err
	}
	if len(body) > MaxBody {
		return Response{Status: resp.StatusCode}, -1, ErrTooLarge
	}
	return Response{Status: resp.StatusCode, Body: body}, parseRetryAfter(resp.Header.Get("Retry-After")), nil
}

// redirect follows a redirect only for a read, and only to the same scheme, host and port. Anywhere else
// the request's credentials would go to a server nobody configured, or evidence would be read from it;
// and a redirected write is resent as a GET, whose answer would look like the write succeeded.
func redirect(req *http.Request, via []*http.Request) error {
	first := via[0]
	switch {
	case first.Method != http.MethodGet:
		return fmt.Errorf("%w: %s %s was redirected; a write is never redirected", ErrRedirect, first.Method, first.URL.Redacted())
	case req.URL.Scheme != first.URL.Scheme || req.URL.Host != first.URL.Host:
		return fmt.Errorf("%w: %s was redirected to another server, %s", ErrRedirect, first.URL.Redacted(), req.URL.Redacted())
	case len(via) >= 10:
		return fmt.Errorf("%w: %s was redirected 10 times", ErrRedirect, first.URL.Redacted())
	}
	return nil
}

func transient(method string, status int, err error) bool {
	if method != http.MethodGet {
		return false
	}
	if err != nil {
		var ne net.Error
		timedOut := errors.As(err, &ne) && ne.Timeout()
		return !timedOut && !errors.Is(err, ErrTooLarge) && !errors.Is(err, ErrRedirect) && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
	}
	switch status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// parseRetryAfter reads a Retry-After header in seconds or as an HTTP date, capped at maxWait; -1
// when absent or unreadable.
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return -1
	}
	if s, err := strconv.Atoi(v); err == nil && s >= 0 {
		return min(time.Duration(s)*time.Second, maxWait)
	}
	if t, err := http.ParseTime(v); err == nil {
		return min(max(time.Until(t), 0), maxWait)
	}
	return -1
}

// Excerpt is the start of a failed answer's body, for an error message: bodies can be whole HTML
// pages or stack traces.
func Excerpt(body []byte) string {
	const n = 512
	s := strings.TrimSpace(string(body))
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}
