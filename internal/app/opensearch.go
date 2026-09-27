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

	"github.com/Bisman-Singh/sievelog/internal/analyze"
	"github.com/Bisman-Singh/sievelog/internal/source/opensearch"
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
	c := &opensearch.Client{Base: o.URL, Username: o.Username, InsecureSkipVerify: o.InsecureSkipVerify}
	if o.PasswordEnv != "" {
		c.Password = os.Getenv(o.PasswordEnv)
	}
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
		src := "opensearch " + o.Name
		cl, err := o.client()
		if err != nil {
			gaps = append(gaps, analyze.Gap{Source: src, Origin: o.URL, Key: "opensearch-unreadable", Reason: err.Error()})
			continue
		}
		cat, err := cl.Catalog(ctx)
		if err != nil {
			gaps = append(gaps, analyze.Gap{Source: src, Origin: o.URL, Key: "opensearch-unreadable", Reason: err.Error()})
			continue
		}
		r := &opensearch.Reader{C: cl, AuditIndex: o.AuditIndex, DashboardsIndex: o.DashboardsIndex, ProveLive: o.ProveLive}
		res := r.Read(ctx, from, now)
		rep.Evidence.OpenSearchUses += len(res.Uses)
		rep.Evidence.OpenSearchAuditLines += res.Lines
		for _, g := range res.Gaps {
			gaps = append(gaps, analyze.Gap{Source: src, Origin: g.Origin, Key: g.Key, Reason: g.Reason})
		}
		for _, n := range res.Notes {
			rep.Notes = append(rep.Notes, src+": "+n)
		}
		for _, svc := range services {
			var idx []string
			for _, i := range o.Indices {
				idx = append(idx, strings.ReplaceAll(i, "{service}", svc))
			}
			scope := opensearch.Scope{Indices: idx, ServiceField: o.ServiceField, Service: svc}.Expand(cat)
			scope, sg, notes := cl.VerifyScope(ctx, scope)
			for _, g := range sg {
				gaps = append(gaps, analyze.Gap{Source: src, Origin: g.Origin, Key: g.Key, Reason: g.Reason})
			}
			for _, n := range notes {
				rep.Notes = append(rep.Notes, src+": "+n)
			}
			for _, u := range res.Uses {
				if u.CannotRead(scope) {
					continue
				}
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
				if u.Opaque {
					why += "; its query is not interpreted"
				} else if len(u.Query) > 0 {
					why += "; its query does not provably select only other services"
				}
				readers = append(readers, analyze.ScopedReader{Service: svc, Source: src, Origin: u.Source + " " + u.Origin, Expr: string(u.Query), Reason: why})
			}
		}
	}
	return readers, gaps
}
