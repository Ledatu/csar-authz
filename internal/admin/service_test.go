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

type failingAuditStore struct{}

func (failingAuditStore) Record(context.Context, *audit.Event) error {
	return errors.New("audit write failed")
}

func (failingAuditStore) List(context.Context, *audit.ListFilter) (*audit.ListResult, error) {
	return nil, errors.New("not implemented")
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

func TestSvcAssignRole_AuditFailureStill204(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	must(t, s.CreateRole(ctx, &store.Role{Name: "tenant_admin"}))

	eng := engine.New(s)
	cfg := &authzconfig.AdminConfig{AuditRequired: true}
	h := New(eng, failingAuditStore{}, slog.Default(), cfg)
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
	h := New(eng, nil, slog.Default(), &authzconfig.AdminConfig{})
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
