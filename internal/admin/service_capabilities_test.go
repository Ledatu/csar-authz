package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ledatu/csar-authz/internal/config"
	"github.com/ledatu/csar-authz/internal/store"
	"github.com/ledatu/csar-core/authzconfig"
	"github.com/ledatu/csar-core/gatewayctx"
	"gopkg.in/yaml.v3"
)

func capabilitySetup(t *testing.T) (*testEnv, *config.Config, *http.ServeMux) {
	t.Helper()
	e, cfg, _ := decisionSetup(t)
	must(t, e.store.CreateRole(context.Background(), &store.Role{Name: "other_role"}))
	cfg.Policy.Roles = []authzconfig.RoleConfig{{Name: "report_reader"}, {Name: "other_role"}}
	cfg.Admin.ServiceAssignableRoles = []string{"report_reader", "other_role"}
	cfg.ServicePolicies.Services = []authzconfig.ServiceCapability{
		{Subject: "svc:writer", Operations: []authzconfig.ServiceOperation{
			{Operation: "grant_role", Profiles: []string{"reports"}, Roles: []string{"report_reader"}},
			{Operation: "revoke_role", Profiles: []string{"reports"}, Roles: []string{"report_reader"}},
		}},
		{Subject: "svc:reader", Operations: []authzconfig.ServiceOperation{
			{Operation: "list_subject_scopes", Profiles: []string{"reports"}, SubjectModes: []string{"request_bound"}},
			{Operation: "list_scope_assignments", Profiles: []string{"reports"}},
			{Operation: "query_assignments", Profiles: []string{"reports"}},
		}},
		{Subject: "svc:worker", Operations: []authzconfig.ServiceOperation{{Operation: "list_subject_scopes", Profiles: []string{"reports"}, SubjectModes: []string{"background"}}}},
	}
	raw, err := yaml.Marshal(cfg)
	must(t, err)
	cfg, err = config.LoadFromBytes(raw)
	must(t, err)
	e.handler.SetConfig(&cfg.Admin)
	mux := http.NewServeMux()
	e.handler.RegisterServiceRoutes(mux)
	must(t, e.handler.RegisterServiceDecisions(mux, cfg))
	return e, cfg, mux
}

func capabilityCall(mux http.Handler, id gatewayctx.Identity, method, path, body string, mutate func(*http.Request)) int {
	w := decisionCall(mux, id, body, func(r *http.Request) {
		r.Method = method
		r.URL.Path = path
		if mutate != nil {
			mutate(r)
		}
	})
	return w.Code
}

func TestServiceRoleCapabilitiesAreIsolatedAndRetainCeiling(t *testing.T) {
	e, cfg, mux := capabilitySetup(t)
	path := "/svc/tenants/workspace:north-branch/members/target/roles"
	for _, entry := range []struct{ service, path, body string }{
		{"svc:reader", path, `{"role":"report_reader"}`},
		{"svc:other", path, `{"role":"report_reader"}`},
		{"svc:writer", path, `{"role":"other_role"}`},
		{"svc:writer", strings.Replace(path, "workspace:", "foreign:", 1), `{"role":"report_reader"}`},
		{"svc:writer", strings.Replace(path, "workspace:north-branch", "workspace:", 1), `{"role":"report_reader"}`},
	} {
		if status := capabilityCall(mux, decisionIdentity(entry.service), "POST", entry.path, entry.body, nil); status != 403 {
			t.Fatal("cross-capability write", entry, status)
		}
	}
	// Expanding caller-owned policy/ceiling after registration cannot broaden the
	// immutable operation. The current global ceiling may only narrow it further.
	cfg.ServicePolicies.Services[0].Operations[0].Roles = append(cfg.ServicePolicies.Services[0].Operations[0].Roles, "other_role")
	cfg.ServicePolicies.DecisionProfiles[0].Bindings[0].ScopeIDPrefix = "foreign:"
	if status := capabilityCall(mux, decisionIdentity("svc:writer"), "POST", path, `{"role":"other_role"}`, nil); status != 403 {
		t.Fatal("startup role policy mutated", status)
	}
	if status := capabilityCall(mux, decisionIdentity("svc:writer"), "POST", path, `{"role":"report_reader"}`, nil); status != 204 {
		t.Fatal("configured grant denied", status)
	}
	result, err := e.store.ListScopeAssignments(context.Background(), "tenant", "workspace:north-branch")
	must(t, err)
	if len(result) != 2 {
		t.Fatal("grant not applied", result)
	}
	if status := capabilityCall(mux, decisionIdentity("svc:reader"), "DELETE", path+"/report_reader", "", nil); status != 403 {
		t.Fatal("read capability revoked role", status)
	}
	if status := capabilityCall(mux, decisionIdentity("svc:writer"), "DELETE", path+"/report_reader", "", nil); status != 204 {
		t.Fatal("configured revoke denied", status)
	}
	cfg.Admin.ServiceAssignableRoles = []string{"other_role"}
	if status := capabilityCall(mux, decisionIdentity("svc:writer"), "POST", path, `{"role":"report_reader"}`, nil); status != 403 {
		t.Fatal("global ceiling lost", status)
	}
}

func TestServiceListingCapabilitiesFilterScopesAndBindSubjects(t *testing.T) {
	e, _, mux := capabilitySetup(t)
	must(t, e.engine.AssignRole(context.Background(), "owner", "report_reader", "tenant", "foreign:north-branch"))
	must(t, e.engine.AssignRole(context.Background(), "owner", "report_reader", "platform", ""))
	w := decisionCall(mux, decisionIdentity("svc:reader"), "", func(r *http.Request) { r.Method = "GET"; r.URL.Path = "/svc/subjects/owner/scopes" })
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var out svcScopesResponse
	must(t, json.Unmarshal(w.Body.Bytes(), &out))
	if len(out.Scopes) != 1 || out.Scopes[0].ScopeID != "workspace:north-branch" {
		t.Fatal("out-of-profile scopes leaked", out)
	}
	for _, entry := range []struct{ service, path string }{
		{"svc:reader", "/svc/subjects/other/scopes"},
		{"svc:writer", "/svc/subjects/owner/scopes"},
		{"svc:other", "/svc/subjects/owner/scopes"},
		{"svc:reader", "/svc/tenants/foreign:north-branch/assignments"},
		{"svc:worker", "/svc/tenants/workspace:north-branch/assignments"},
	} {
		if status := capabilityCall(mux, decisionIdentity(entry.service), "GET", entry.path, "", nil); status != 403 {
			t.Fatal(entry, status)
		}
	}
	expired := decisionIdentity("svc:reader")
	expired.Origin.ExpiresAt = time.Now().Add(-time.Second)
	if status := capabilityCall(mux, expired, "GET", "/svc/subjects/owner/scopes", "", nil); status != 403 {
		t.Fatal("expired original caller listed scopes", status)
	}
	worker := decisionIdentity("svc:worker")
	worker.Origin = nil
	if status := capabilityCall(mux, worker, "GET", "/svc/subjects/owner/scopes", "", nil); status != 200 {
		t.Fatal("explicit background list denied", status)
	}
	if status := capabilityCall(mux, decisionIdentity("svc:reader"), "GET", "/svc/tenants/workspace:north-branch/assignments", "", nil); status != 200 {
		t.Fatal(status)
	}
	for _, body := range []string{`{"tenant_ids":["workspace:north-branch","foreign:north-branch"]}`, `{"tenant_ids":["workspace:"]}`} {
		if status := capabilityCall(mux, decisionIdentity("svc:reader"), "POST", "/svc/assignments/query", body, nil); status != 403 {
			t.Fatal("mixed query admitted", status)
		}
	}
	if status := capabilityCall(mux, decisionIdentity("svc:reader"), "POST", "/svc/assignments/query", `{"tenant_ids":["workspace:north-branch"]}`, nil); status != 200 {
		t.Fatal(status)
	}
}

func TestServiceCapabilitiesRequireVerifiedIngressAndStrictWrites(t *testing.T) {
	_, _, mux := capabilitySetup(t)
	path := "/svc/tenants/workspace:north-branch/members/target/roles"
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.TLS = nil },
		func(r *http.Request) { r.TLS.VerifiedChains = nil },
		func(r *http.Request) { r.TLS.PeerCertificates[0].Subject.CommonName = "other" },
	} {
		if status := capabilityCall(mux, decisionIdentity("svc:writer"), "POST", path, `{"role":"report_reader"}`, mutate); status != 403 {
			t.Fatal(status)
		}
	}
	id := decisionIdentity("svc:writer")
	id.Caller = nil
	if status := capabilityCall(mux, id, "POST", path, `{"role":"report_reader"}`, nil); status != 403 {
		t.Fatal("svc prefix substituted for STS", status)
	}
	for _, body := range []string{`{"role":"report_reader","role":"other_role"}`, `{"role":"report_reader","unknown":true}`, `{"role":"report_reader"} {}`} {
		if status := capabilityCall(mux, decisionIdentity("svc:writer"), "POST", path, body, nil); status != 400 {
			t.Fatal("ambiguous write admitted", body, status)
		}
	}
}
