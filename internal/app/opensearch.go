package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Bisman-Singh/zeroreads/internal/analyze"
	"github.com/Bisman-Singh/zeroreads/internal/source/opensearch"
)

// OpenSearchConfig is one OpenSearch cluster that receives the analysed logs.
type OpenSearchConfig struct {
	Name               string `yaml:"name"` // referenced by a sink's opensearch key
	URL                string `yaml:"url"`
	Username           string `yaml:"username"`
	PasswordEnv        string `yaml:"password_env"`
	CAFile             string `yaml:"ca_file"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	AuditIndex         string `yaml:"audit_index"`      // default security-auditlog-*
	DashboardsIndex    string `yaml:"dashboards_index"` // default .kibana*
	ProveLive          bool   `yaml:"prove_live"`
	// Indices holding a service's documents; {service} is replaced by the service name.
	Indices []string `yaml:"indices"`
	// ServiceField is the keyword field holding the service name; empty disables term reasoning.
	ServiceField string `yaml:"service_field"`
}

func (o OpenSearchConfig) client() (*opensearch.Client, error) {
	password, err := secret("evidence.opensearch."+o.Name+".password_env", o.PasswordEnv)
	if err != nil {
		return nil, err
	}
	c := &opensearch.Client{Base: o.URL, Username: o.Username, Password: password, InsecureSkipVerify: o.InsecureSkipVerify}
	if o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s: no certificate found", o.CAFile)
		}
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		c.HTTP = &http.Client{Timeout: 60 * time.Second, Transport: tr}
	}
	return c, nil
}

// openSearchEvidence reads every configured cluster. Each request that may read a service's
// documents becomes a reader of every rule of that service.
func (c *Config) openSearchEvidence(ctx context.Context, from, now time.Time, services []string, rep *Report) ([]analyze.ScopedReader, []analyze.Gap) {
	var readers []analyze.ScopedReader
	var gaps []analyze.Gap
	for _, o := range c.Evidence.OpenSearch {
		r, g := o.evidence(ctx, from, now, services, rep)
		readers, gaps = append(readers, r...), append(gaps, g...)
	}
	return readers, gaps
}

// evidence reads one cluster: its audit log, monitors and saved objects, checked against each
// service's scope.
func (o OpenSearchConfig) evidence(ctx context.Context, from, now time.Time, services []string, rep *Report) ([]analyze.ScopedReader, []analyze.Gap) {
	src := "opensearch " + o.Name
	gap := func(g opensearch.Gap) analyze.Gap {
		return analyze.Gap{Source: src, Origin: g.Origin, Key: g.Key, Reason: g.Reason}
	}
	cl, err := o.client()
	if err != nil {
		return nil, []analyze.Gap{{Source: src, Origin: o.URL, Key: "opensearch-unreadable", Reason: err.Error()}}
	}
	cat, err := cl.Catalog(ctx)
	if err != nil {
		return nil, []analyze.Gap{{Source: src, Origin: o.URL, Key: "opensearch-unreadable", Reason: err.Error()}}
	}
	res := (&opensearch.Reader{Client: cl, AuditIndex: o.AuditIndex, DashboardsIndex: o.DashboardsIndex, ProveLive: o.ProveLive}).Read(ctx, from, now)
	rep.Evidence.OpenSearchUses += len(res.Uses)
	rep.Evidence.OpenSearchAuditLines += res.Lines
	var gaps []analyze.Gap
	for _, g := range res.Gaps {
		gaps = append(gaps, gap(g))
	}
	for _, n := range res.Notes {
		rep.Notes = append(rep.Notes, src+": "+n)
	}
	var readers []analyze.ScopedReader
	for _, svc := range services {
		var idx []string
		for _, i := range o.Indices {
			idx = append(idx, strings.ReplaceAll(i, "{service}", svc))
		}
		scope, scopeGaps, notes := cl.VerifyScope(ctx, opensearch.Scope{Indices: idx, ServiceField: o.ServiceField, Service: svc}.Expand(cat))
		for _, g := range scopeGaps {
			gaps = append(gaps, gap(g))
		}
		for _, n := range notes {
			rep.Notes = append(rep.Notes, src+": "+n)
		}
		for _, u := range res.Uses {
			if !u.CannotRead(scope) {
				readers = append(readers, analyze.ScopedReader{Service: svc, Source: src, Origin: u.Source + " " + u.Origin, Expr: string(u.Query), Reason: whyReads(u, scope)})
			}
		}
	}
	return readers, gaps
}

// whyReads says why a request or stored query may read the scope's documents.
func whyReads(u opensearch.Use, scope opensearch.Scope) string {
	target := "every index"
	if len(u.Indices) > 0 {
		target = strings.Join(u.Indices, ",")
	}
	why := "targets " + target + ", which can hold this service's documents"
	for _, i := range u.Indices {
		if u.Source == "audit" && !strings.HasPrefix(i, "-") && !strings.Contains(i, ":") && scope.Gone(i) {
			why += "; " + i + " no longer exists here and may have been an alias over them"
		}
	}
	switch {
	case u.Opaque:
		why += "; its query is not interpreted"
	case len(u.Query) > 0:
		why += "; its query does not provably select only other services"
	}
	return why
}
