package admin

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ledatu/csar-authz/internal/config"
	"github.com/ledatu/csar-authz/internal/engine"
	"github.com/ledatu/csar-authz/internal/store"
	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/gatewayctx"
)

const decisionConfig = `admin:
  enabled: true
  allowed_client_cn: gateway
  tls: {cert_file: server.pem, key_file: server-key.pem, client_ca_file: router-ca.pem}
service_policies:
  version: 1
  enabled: true
  decision_profiles:
    - id: reports
      audience: https://reports.example.test
      resource: report
      action: read
      bindings:
        - {namespace: workspace, scope_type: tenant, scope_id_prefix: 'workspace:'}
        - {namespace: project, scope_type: tenant, scope_id_prefix: 'project:'}
  services:
    - subject: svc:reader
      operations:
        - {operation: decide, profiles: [reports], subject_modes: [request_bound]}
    - subject: svc:worker
      operations:
        - {operation: decide, profiles: [reports], subject_modes: [background]}
`

func decisionSetup(t *testing.T) (*testEnv, *config.Config, *http.ServeMux) {
	t.Helper()
	e := setup(t)
	must(t, e.store.CreateRole(context.Background(), &store.Role{Name: "report_reader"}))
	must(t, e.store.AddPermission(context.Background(), &store.Permission{Role: "report_reader", Resource: "report", Action: "read"}))
	must(t, e.engine.AssignRole(context.Background(), "owner", "report_reader", "tenant", "workspace:north-branch"))
	cfg, err := config.LoadFromBytes([]byte(decisionConfig))
	must(t, err)
	mux := http.NewServeMux()
	must(t, e.handler.RegisterServiceDecisions(mux, cfg))
	return e, cfg, mux
}

func decisionBody(mode string) string {
	return `{"version":1,"profile":"reports","audience":"https://reports.example.test","subject":"owner","subject_mode":"` + mode + `","resources":[{"namespace":"workspace","id":"north-branch"}]}`
}

func decisionIdentity(service string) gatewayctx.Identity {
	return gatewayctx.Identity{Subject: service, Caller: &caller.Identity{Version: 1, CallerKind: caller.Service, CallerID: service, EffectiveSubject: service, CredentialKind: caller.STS, Assurance: caller.Verified},
		Origin: &gatewayctx.Origin{Caller: &caller.Identity{Version: 1, CallerKind: caller.Agent, CallerID: "agent", OwnerSubject: "owner", EffectiveSubject: "owner", CredentialKind: caller.APIKey, CredentialID: "key", Assurance: caller.Verified}, OperationID: "00000000-0000-4000-8000-000000000001", ExpiresAt: time.Now().Add(time.Minute)}}
}

func decisionCall(mux http.Handler, id gatewayctx.Identity, body string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/svc/decisions/check", strings.NewReader(body))
	peer := &x509.Certificate{Raw: []byte{1}, Subject: pkix.Name{CommonName: "gateway"}}
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}, VerifiedChains: [][]*x509.Certificate{{peer, {Raw: []byte{2}}}}}
	r = r.WithContext(gatewayctx.NewContext(r.Context(), &id))
	if mutate != nil {
		mutate(r)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func TestServiceDecisionsAreCurrentAndNamespaceBound(t *testing.T) {
	e, cfg, mux := decisionSetup(t)
	// Registration owns the immutable startup config, including nested slices.
	cfg.ServicePolicies.Services[0].Operations[0].Profiles[0] = "mutated"
	cfg.ServicePolicies.DecisionProfiles[0].Bindings[0].ScopeIDPrefix = "other:"
	body := strings.Replace(decisionBody("request_bound"), `}]}`, `},{"namespace":"project","id":"north-branch"}]}`, 1)
	w := decisionCall(mux, decisionIdentity("svc:reader"), body, nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var out serviceDecisionResponse
	must(t, json.Unmarshal(w.Body.Bytes(), &out))
	if len(out.Results) != 2 || !out.Results[0].Allowed || out.Results[1].Allowed || out.Results[0].Scope.ID != "workspace:north-branch" || out.Results[1].Scope != nil {
		t.Fatal("namespace authority mixed", out)
	}
	must(t, e.engine.RevokeRole(context.Background(), "owner", "report_reader", "tenant", "workspace:north-branch"))
	w = decisionCall(mux, decisionIdentity("svc:reader"), decisionBody("request_bound"), nil)
	if w.Code != 200 || bytes.Contains(w.Body.Bytes(), []byte(`"allowed":true`)) {
		t.Fatal("revocation cached", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("decision may be cached")
	}
}

func TestServiceDecisionsRejectSubstitutionAndForgedIngress(t *testing.T) {
	_, _, mux := decisionSetup(t)
	for name, mutate := range map[string]func(*gatewayctx.Identity){
		"no metadata":          func(id *gatewayctx.Identity) { id.Caller = nil },
		"unregistered service": func(id *gatewayctx.Identity) { *id = decisionIdentity("svc:other") },
		"human hop":            func(id *gatewayctx.Identity) { id.Caller.CallerKind = caller.Human; id.Caller.OwnerSubject = "owner" },
		"non STS":              func(id *gatewayctx.Identity) { id.Caller.CredentialKind = caller.APIKey },
		"caller mismatch":      func(id *gatewayctx.Identity) { id.Caller.EffectiveSubject = "svc:other" },
		"no owner origin":      func(id *gatewayctx.Identity) { id.Origin = nil },
		"expired origin":       func(id *gatewayctx.Identity) { id.Origin.ExpiresAt = time.Now().Add(-time.Second) },
		"owner substitution":   func(id *gatewayctx.Identity) { id.Origin.Caller.OwnerSubject = "other" },
		"impersonation":        func(id *gatewayctx.Identity) { id.Origin.Caller.EffectiveSubject = "other" },
		"origin only":          func(id *gatewayctx.Identity) { id.Subject = ""; id.Caller = nil },
	} {
		t.Run(name, func(t *testing.T) {
			id := decisionIdentity("svc:reader")
			mutate(&id)
			if w := decisionCall(mux, id, decisionBody("request_bound"), nil); w.Code != 403 {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
	for name, mutate := range map[string]func(*http.Request){
		"plaintext":        func(r *http.Request) { r.TLS = nil },
		"unverified chain": func(r *http.Request) { r.TLS.VerifiedChains = nil },
		"wrong pin":        func(r *http.Request) { r.TLS.PeerCertificates[0].Subject.CommonName = "other" },
		"wrong leaf": func(r *http.Request) {
			r.TLS.VerifiedChains[0][0] = &x509.Certificate{Raw: []byte{3}, Subject: pkix.Name{CommonName: "gateway"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			if w := decisionCall(mux, decisionIdentity("svc:reader"), decisionBody("request_bound"), mutate); w.Code != 403 {
				t.Fatal("unverified ingress accepted", w.Code)
			}
		})
	}
	for _, body := range []string{
		strings.Replace(decisionBody("request_bound"), `"subject":"owner"`, `"subject":"other"`, 1),
		strings.Replace(decisionBody("request_bound"), `"reports","audience"`, `"unknown","audience"`, 1),
		strings.Replace(decisionBody("request_bound"), "reports.example.test", "foreign.example.test", 1),
		strings.Replace(decisionBody("request_bound"), `"workspace"`, `"unknown"`, 1),
		decisionBody("background"),
	} {
		if w := decisionCall(mux, decisionIdentity("svc:reader"), body, nil); w.Code != 403 {
			t.Fatal("substitution accepted", w.Code)
		}
	}
	id := decisionIdentity("svc:worker")
	id.Origin = nil
	if w := decisionCall(mux, id, decisionBody("background"), nil); w.Code != 200 {
		t.Fatal("configured durable actor check denied", w.Code)
	}
}

func TestServiceDecisionRequestBounds(t *testing.T) {
	_, _, mux := decisionSetup(t)
	for _, body := range []string{`{}`, `null`, decisionBody("request_bound") + `{}`, strings.Replace(decisionBody("request_bound"), `"version":1`, `"version":1,"Version":1`, 1), strings.Replace(decisionBody("request_bound"), `"version":1`, `"version":1,"resource":"arbitrary"`, 1), strings.Replace(decisionBody("request_bound"), `"id":"north-branch"`, `"id":"north-branch","id":"other"`, 1), strings.Replace(decisionBody("request_bound"), `"id":"north-branch"`, `"id":"`+strings.Repeat("x", authntokens.MaxCandidateRequestBytes)+`"`, 1)} {
		if w := decisionCall(mux, decisionIdentity("svc:reader"), body, nil); w.Code != 400 {
			t.Fatal("malformed request accepted", w.Code)
		}
	}
	var in serviceDecisionRequest
	must(t, json.Unmarshal([]byte(decisionBody("request_bound")), &in))
	in.Resources = append(in.Resources, in.Resources[0])
	body, err := json.Marshal(in)
	must(t, err)
	if w := decisionCall(mux, decisionIdentity("svc:reader"), string(body), nil); w.Code != 400 {
		t.Fatal("duplicate resource accepted")
	}
	in.Resources = nil
	for i := 0; i <= authntokens.MaxDecisionResources; i++ {
		in.Resources = append(in.Resources, authntokens.ResourceRef{Namespace: "workspace", ID: strings.Repeat("x", i+1)})
	}
	body, err = json.Marshal(in)
	must(t, err)
	if w := decisionCall(mux, decisionIdentity("svc:reader"), string(body), nil); w.Code != 400 {
		t.Fatal("oversized batch accepted")
	}
}

type interruptedDecisions struct {
	underlying *engine.Engine
	calls      int
}

func (f *interruptedDecisions) CheckAccess(ctx context.Context, subject, scope, id, resource, action string) (*engine.Result, error) {
	f.calls++
	if f.calls == 2 {
		return nil, errors.New("private backend failure")
	}
	return f.underlying.CheckAccess(ctx, subject, scope, id, resource, action)
}

func TestServiceDecisionFailureReleasesNoPartialResults(t *testing.T) {
	e, cfg, _ := decisionSetup(t)
	d := &serviceDecisionHandler{engine: &interruptedDecisions{underlying: e.engine}, policies: cfg.ServicePolicies, gatewayCN: "gateway"}
	body := strings.Replace(decisionBody("request_bound"), `}]}`, `},{"namespace":"workspace","id":"other"}]}`, 1)
	w := decisionCall(http.HandlerFunc(d.check), decisionIdentity("svc:reader"), body, nil)
	if w.Code != 503 || strings.Contains(w.Body.String(), "allowed") || strings.Contains(w.Body.String(), "private backend") {
		t.Fatal("partial authority or private error released", w.Code, w.Body.String())
	}
}

func TestServiceDecisionCancellationReleasesNothing(t *testing.T) {
	_, _, mux := decisionSetup(t)
	w := decisionCall(mux, decisionIdentity("svc:reader"), decisionBody("request_bound"), func(r *http.Request) {
		ctx, cancel := context.WithCancel(r.Context())
		cancel()
		*r = *r.WithContext(ctx)
	})
	if w.Code != 503 || strings.Contains(w.Body.String(), "allowed") {
		t.Fatal("cancelled operation released authority", w.Code, w.Body.String())
	}
}
