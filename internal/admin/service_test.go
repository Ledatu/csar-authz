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

	r := reqSvcAssignRole("tenant-1", "user-1", "tenant_admin")
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

	r := reqSvcAssignRole("tenant-1", "user-1", "tenant_admin")
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
	mux.ServeHTTP(w, reqSvcAssignRole("tenant-1", "user-1", "tenant_admin"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 with empty allowlist", w.Code)
	}
	roles, err := s.GetSubjectRoles(context.Background(), "user-1", "tenant", "tenant-1")
	must(t, err)
	if len(roles) != 0 {
		t.Fatalf("assignment created despite empty allowlist: %v", roles)
	}
}

func TestSvcAssignRole_AllowlistedRoleSucceeds(t *testing.T) {
	_, mux, s := newSvcHandler(t, "tenant_admin")

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, reqSvcAssignRole("tenant-1", "user-1", "tenant_admin"))
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (body %s)", w.Code, w.Body.String())
	}
	roles, err := s.GetSubjectRoles(context.Background(), "user-1", "tenant", "tenant-1")
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
