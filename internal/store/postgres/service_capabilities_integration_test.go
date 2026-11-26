package postgres

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ledatu/csar-authz/internal/admin"
	"github.com/ledatu/csar-authz/internal/config"
	"github.com/ledatu/csar-authz/internal/engine"
	"github.com/ledatu/csar-authz/internal/store"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/gatewayctx"
)

func TestServiceCapabilitiesRetainTransactionalAudit(t *testing.T) {
	s := auditFixture(t)
	ctx := actorContext()
	if err := s.CreateRole(ctx, &store.Role{Name: "reader"}); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadFromBytes([]byte(`admin:
  enabled: true
  allowed_client_cn: gateway
  tls: {cert_file: server.pem, key_file: key.pem, client_ca_file: ca.pem}
  service_assignable_roles: [reader]
policy:
  roles: [{name: reader}]
service_policies:
  version: 1
  enabled: true
  decision_profiles:
    - id: reports
      audience: https://reports.example.test
      resource: report
      action: read
      bindings: [{namespace: workspace, scope_type: tenant, scope_id_prefix: 'workspace:'}]
  services:
    - subject: svc:writer
      operations:
        - {operation: grant_role, profiles: [reports], roles: [reader]}
        - {operation: revoke_role, profiles: [reports], roles: [reader]}
`))
	if err != nil {
		t.Fatal(err)
	}
	h := admin.New(engine.New(s), nil, nil, slog.Default(), &cfg.Admin)
	h.SetTransactionalAudit(true)
	mux := http.NewServeMux()
	h.RegisterServiceRoutes(mux)
	if err := h.RegisterServiceDecisions(mux, cfg); err != nil {
		t.Fatal(err)
	}
	call := func(method, path string) int {
		r := httptest.NewRequest(method, path, strings.NewReader(`{"role":"reader"}`))
		peer := &x509.Certificate{Raw: []byte{1}, Subject: pkix.Name{CommonName: "gateway"}}
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}, VerifiedChains: [][]*x509.Certificate{{peer, {Raw: []byte{2}}}}}
		id := gatewayctx.Identity{Subject: "svc:writer", Caller: &caller.Identity{Version: 1, CallerKind: caller.Service, CallerID: "svc:writer", EffectiveSubject: "svc:writer", CredentialKind: caller.STS, Assurance: caller.Verified}}
		r = r.WithContext(gatewayctx.NewContext(r.Context(), &id))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w.Code
	}
	path := "/svc/tenants/workspace:north/members/owner/roles"
	if status := call("POST", path); status != 204 {
		t.Fatal(status)
	}
	var actor string
	if err := s.pool.QueryRow(context.Background(), `SELECT convert_from(payload,'UTF8')::jsonb->>'actor' FROM csar_audit_outbox WHERE convert_from(payload,'UTF8')::jsonb->>'action'='role.assign'`).Scan(&actor); err != nil || actor != "svc:writer" {
		t.Fatal("lost service audit", actor, err)
	}
	if _, err := s.pool.Exec(ctx, `DROP TABLE csar_audit_outbox`); err != nil {
		t.Fatal(err)
	}
	if status := call("DELETE", path+"/reader"); status != 500 {
		t.Fatal("unaudited revoke succeeded", status)
	}
	roles, err := s.GetSubjectRoles(ctx, "owner", "tenant", "workspace:north")
	if err != nil || len(roles) != 1 {
		t.Fatal("revoke survived audit failure", roles, err)
	}
	if status := call("POST", strings.Replace(path, "/owner/", "/other/", 1)); status != 500 {
		t.Fatal("unaudited grant succeeded", status)
	}
	roles, err = s.GetSubjectRoles(ctx, "other", "tenant", "workspace:north")
	if err != nil || len(roles) != 0 {
		t.Fatal("grant survived audit failure", roles, err)
	}
}
