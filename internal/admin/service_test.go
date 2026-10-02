package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ledatu/csar-authz/internal/engine"
	"github.com/ledatu/csar-authz/internal/store"
	"github.com/ledatu/csar-authz/internal/store/memory"
	"github.com/ledatu/csar-core/audit"
	"github.com/ledatu/csar-core/authzconfig"
	"github.com/ledatu/csar-core/gatewayctx"
)

type failingAuditRecorder struct{}

func (failingAuditRecorder) Record(context.Context, *audit.Event) error {
	return errors.New("audit write failed")
}

func reqSvcAssignRole(tenantID, targetSubject, role string) *http.Request {
	body, _ := json.Marshal(map[string]string{"role": role})
	r := httptest.NewRequest(http.MethodPost,
		"/svc/tenants/"+tenantID+"/members/"+targetSubject+"/roles",
		bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	ctx := gatewayctx.NewContext(r.Context(), &gatewayctx.Identity{Subject: "svc:aurumskynet-campaigns"})
	return r.WithContext(ctx)
}

func reqSvcRevokeRole(tenantID, targetSubject, role string) *http.Request {
	r := httptest.NewRequest(
		http.MethodDelete,
		"/svc/tenants/"+tenantID+"/members/"+targetSubject+"/roles/"+role,
		nil,
	)
	ctx := gatewayctx.NewContext(r.Context(), &gatewayctx.Identity{Subject: "svc:aurumskynet-campaigns"})
	return r.WithContext(ctx)
}

func TestSvcAssignRole_AuditFailureStill204(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	must(t, s.CreateRole(ctx, &store.Role{Name: "tenant_admin"}))

	eng := engine.New(s)
	cfg := &authzconfig.AdminConfig{AuditRequired: true, ServiceAssignableRoles: []string{"tenant_admin"}}
	h := New(eng, failingAuditRecorder{}, nil, slog.Default(), cfg)
	mux := http.NewServeMux()
	h.RegisterServiceRoutes(mux)

	r := reqSvcAssignRole("wildberries:tenant-1", "user-1", "tenant_admin")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 after successful role grant even when audit fails, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSvcAssignRole_AssignFailureReturns500(t *testing.T) {
	s := memory.New()
	eng := engine.New(s)
	h := New(eng, nil, nil, slog.Default(), &authzconfig.AdminConfig{ServiceAssignableRoles: []string{"tenant_admin"}})
	mux := http.NewServeMux()
	h.RegisterServiceRoutes(mux)

	r := reqSvcAssignRole("wildberries:tenant-1", "user-1", "tenant_admin")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when role does not exist, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "failed to assign role") {
		t.Fatalf("expected error body to mention assign failure, got %q", w.Body.String())
	}
}

func TestSvcRevokeRole_AuditFailureStill204(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	must(t, s.CreateRole(ctx, &store.Role{Name: "tenant_admin"}))
	must(t, s.AssignRole(ctx, "user-1", "tenant_admin", "tenant", "tenant-1"))

	eng := engine.New(s)
	cfg := &authzconfig.AdminConfig{AuditRequired: true, ServiceAssignableRoles: []string{"tenant_admin"}}
	h := New(eng, failingAuditRecorder{}, nil, slog.Default(), cfg)
	mux := http.NewServeMux()
	h.RegisterServiceRoutes(mux)

	r := reqSvcRevokeRole("tenant-1", "user-1", "tenant_admin")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 after successful role revoke even when audit fails, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSvcRevokeRole_MissingAssignmentStill204(t *testing.T) {
	s := memory.New()
	eng := engine.New(s)
	h := New(eng, nil, nil, slog.Default(), &authzconfig.AdminConfig{ServiceAssignableRoles: []string{"tenant_admin"}})
	mux := http.NewServeMux()
	h.RegisterServiceRoutes(mux)

	r := reqSvcRevokeRole("tenant-1", "user-1", "tenant_admin")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 when assignment does not exist, got %d: %s", w.Code, w.Body.String())
	}
}

func newSvcHandler(t *testing.T, assignable ...string) (*Handler, *http.ServeMux, store.Store) {
	t.Helper()
	s := memory.New()
	ctx := context.Background()
	must(t, s.CreateRole(ctx, &store.Role{Name: "tenant_admin"}))
	must(t, s.CreateRole(ctx, &store.Role{Name: "platform_admin"}))
	must(t, s.CreateRole(ctx, &store.Role{Name: "admin"}))

	cfg := &authzconfig.AdminConfig{ServiceAssignableRoles: assignable}
	h := New(engine.New(s), nil, nil, slog.Default(), cfg)
	mux := http.NewServeMux()
	h.RegisterServiceRoutes(mux)
	return h, mux, s
}

func TestSvcAssignRole_RejectsRoleOutsideAllowlist(t *testing.T) {
	_, mux, s := newSvcHandler(t, "tenant_admin")

	for _, role := range []string{"platform_admin", "admin"} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, reqSvcAssignRole("tenant-1", "user-1", role))
		if w.Code != http.StatusForbidden {
			t.Fatalf("assign %s: status = %d, want 403 (body %s)", role, w.Code, w.Body.String())
		}
		roles, err := s.GetSubjectRoles(context.Background(), "user-1", "tenant", "tenant-1")
		must(t, err)
		if len(roles) != 0 {
			t.Fatalf("assign %s: assignment was created despite rejection: %v", role, roles)
		}
	}
}

func TestSvcAssignRole_EmptyAllowlistDeniesEverything(t *testing.T) {
	_, mux, s := newSvcHandler(t)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, reqSvcAssignRole("wildberries:tenant-1", "user-1", "tenant_admin"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 with empty allowlist", w.Code)
	}
	roles, err := s.GetSubjectRoles(context.Background(), "user-1", "tenant", "wildberries:tenant-1")
	must(t, err)
	if len(roles) != 0 {
		t.Fatalf("assignment created despite empty allowlist: %v", roles)
	}
}

func TestSvcAssignRole_AllowlistedRoleSucceeds(t *testing.T) {
	_, mux, s := newSvcHandler(t, "tenant_admin")

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, reqSvcAssignRole("wildberries:tenant-1", "user-1", "tenant_admin"))
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (body %s)", w.Code, w.Body.String())
	}
	roles, err := s.GetSubjectRoles(context.Background(), "user-1", "tenant", "wildberries:tenant-1")
	must(t, err)
	if len(roles) != 1 || roles[0] != "tenant_admin" {
		t.Fatalf("roles = %v, want [tenant_admin]", roles)
	}
}

func TestSvcRevokeRole_RejectsRoleOutsideAllowlist(t *testing.T) {
	_, mux, s := newSvcHandler(t, "tenant_admin")
	must(t, s.AssignRole(context.Background(), "user-1", "platform_admin", "tenant", "tenant-1"))

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, reqSvcRevokeRole("tenant-1", "user-1", "platform_admin"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	roles, err := s.GetSubjectRoles(context.Background(), "user-1", "tenant", "tenant-1")
	must(t, err)
	if len(roles) != 1 {
		t.Fatalf("assignment removed despite rejection: %v", roles)
	}
}

func reqSvcQueryAssignments(subject, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/svc/assignments/query", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	ctx := gatewayctx.NewContext(r.Context(), &gatewayctx.Identity{Subject: subject})
	return r.WithContext(ctx)
}

func TestSvcQueryAssignments_ReturnsRequestedTenantsOnly(t *testing.T) {
	_, mux, s := newSvcHandler(t)
	ctx := context.Background()
	must(t, s.AssignRole(ctx, "user-1", "tenant_admin", "tenant", "wildberries:a"))
	must(t, s.AssignRole(ctx, "user-2", "admin", "tenant", "wildberries:a"))
	must(t, s.AssignRole(ctx, "user-3", "tenant_admin", "tenant", "wildberries:b"))
	must(t, s.AssignRole(ctx, "user-4", "tenant_admin", "tenant", "wildberries:c"))
	must(t, s.AssignRole(ctx, "user-5", "platform_admin", "platform", ""))

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, reqSvcQueryAssignments("svc:aurumskynet-campaigns",
		`{"tenant_ids":["wildberries:b","wildberries:a","wildberries:a","wildberries:missing"]}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body.String())
	}

	var resp svcAssignmentQueryResponse
	must(t, json.Unmarshal(w.Body.Bytes(), &resp))
	want := []tenantAssignmentDTO{
		{TenantID: "wildberries:a", Subject: "user-1", Role: "tenant_admin"},
		{TenantID: "wildberries:a", Subject: "user-2", Role: "admin"},
		{TenantID: "wildberries:b", Subject: "user-3", Role: "tenant_admin"},
	}
	if len(resp.Assignments) != len(want) {
		t.Fatalf("assignments = %+v, want %+v", resp.Assignments, want)
	}
	for i := range want {
		if resp.Assignments[i] != want[i] {
			t.Fatalf("assignments[%d] = %+v, want %+v", i, resp.Assignments[i], want[i])
		}
	}
}

func TestSvcQueryAssignments_RejectsInvalidRequests(t *testing.T) {
	_, mux, _ := newSvcHandler(t)
	tooMany := make([]string, maxSvcAssignmentQueryTenants+1)
	for i := range tooMany {
		tooMany[i] = "wildberries:x"
	}
	tooManyBody, _ := json.Marshal(svcAssignmentQueryRequest{TenantIDs: tooMany})

	cases := []struct {
		name    string
		subject string
		body    string
		want    int
	}{
		{"user subject", "user-1", `{"tenant_ids":["wildberries:a"]}`, http.StatusForbidden},
		{"no subject", "", `{"tenant_ids":["wildberries:a"]}`, http.StatusUnauthorized},
		{"empty list", "svc:aurumskynet-campaigns", `{"tenant_ids":[]}`, http.StatusBadRequest},
		{"empty id", "svc:aurumskynet-campaigns", `{"tenant_ids":["wildberries:a",""]}`, http.StatusBadRequest},
		{"too many", "svc:aurumskynet-campaigns", string(tooManyBody), http.StatusBadRequest},
		{"malformed", "svc:aurumskynet-campaigns", `{`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, reqSvcQueryAssignments(tc.subject, tc.body))
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", w.Code, tc.want, w.Body.String())
			}
		})
	}
}
