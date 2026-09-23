package gen

// The ground-truth corpus. Every line the generator emits comes from exactly one of these
// templates, so per-template counts and bytes are known exactly.
//
// Templates are written as space-separated tokens. A token of the form {kind} is a variable
// that always renders as exactly one token (no spaces), so a template's token count is fixed.
// The corpus deliberately contains the cases the analyzer has to get right:
//   - high-volume noise (health checks, heartbeats)
//   - a constant template with no variables
//   - two templates of the same length that differ in one literal (cache hit / miss)
//   - a short template and a longer sibling sharing its prefix and suffix (user ... logged in)
//   - a variable whose values differ between stored examples and alerts (status codes)
//   - a value covered by a masking rule (IP addresses)
//   - a raw line that literally contains a mask token's text (<ip>)
//   - error and warn severities
//   - structured JSON records where only the msg field is templated

// Service is one log stream, as one workload would emit it.
type Service struct {
	Name      string
	JSON      bool // records are JSON objects; the template covers only the msg field
	Templates []Template
}

// Template is one ground-truth log shape.
type Template struct {
	ID       string
	Severity string
	Pattern  string // tokens; {kind} marks a single-token variable
	Weight   int    // relative frequency within its service
}

// Corpus returns the ground-truth services. The slice is rebuilt on every call so callers
// cannot mutate shared state.
func Corpus() []Service {
	return []Service{
		{
			Name: "checkout",
			Templates: []Template{
				{ID: "health", Severity: "INFO", Pattern: "INFO GET /healthz 200 {duration}", Weight: 400},
				{ID: "heartbeat", Severity: "INFO", Pattern: "INFO heartbeat ok", Weight: 100},
				{ID: "request", Severity: "INFO", Pattern: "INFO request {reqid} status {status} took {duration}", Weight: 250},
				{ID: "cache-hit", Severity: "DEBUG", Pattern: "DEBUG cache hit key {hex}", Weight: 80},
				{ID: "cache-miss", Severity: "DEBUG", Pattern: "DEBUG cache miss key {hex}", Weight: 20},
				{ID: "retry", Severity: "WARN", Pattern: "WARN retrying connection to {ip} attempt {small}", Weight: 30},
				{ID: "payment-declined", Severity: "ERROR", Pattern: "ERROR payment {payid} declined code {declinecode}", Weight: 10},
			},
		},
		{
			Name: "auth",
			Templates: []Template{
				{ID: "login", Severity: "INFO", Pattern: "INFO user {user} logged in", Weight: 200},
				{ID: "login-mfa-fail", Severity: "WARN", Pattern: "WARN user {user} failed MFA and was logged in", Weight: 15},
				{ID: "placeholder", Severity: "INFO", Pattern: "INFO config placeholder <ip> unresolved for {user}", Weight: 5},
			},
		},
		{
			Name: "orders",
			JSON: true,
			Templates: []Template{
				{ID: "order-created", Severity: "INFO", Pattern: "order {orderid} created for {user}", Weight: 150},
				{ID: "order-route", Severity: "INFO", Pattern: "handled route in {duration}", Weight: 300},
				{ID: "order-failed", Severity: "ERROR", Pattern: "order {orderid} failed at step {step}", Weight: 10},
			},
		},
	}
}
