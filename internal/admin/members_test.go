package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ledatu/csar-core/audit"
	"github.com/ledatu/csar-core/gatewayctx"
)

type captureAuditRecorder struct {
	events []*audit.Event
}

func (r *captureAuditRecorder) Record(_ context.Context, event *audit.Event) error {
	cp := *event
	r.events = append(r.events, &cp)
	return nil
}

func reqWithSubjectJSON(method, path, subject string, body any) *http.Request {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}

	r := httptest.NewRequest(method, path, &buf)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}

	ctx := gatewayctx.NewContext(r.Context(), &gatewayctx.Identity{Subject: subject})
	return r.WithContext(ctx)
}

func TestListPlatformMembers_GroupsRoles(t *testing.T) {
	env := setup(t)
	ctx := context.Background()

	setupPlatformAdmin(t, env, "root")
	setupPlatformManager(t, env, "alice")
	must(t, env.store.AssignRole(ctx, "alice", "platform_admin", "platform", ""))

	r := reqWithSubject("GET", "/admin/platform/members", "root")
	w := httptest.NewRecorder()
	env.mux.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp listPlatformMembersResponse
	must(t, json.NewDecoder(w.Body).Decode(&resp))

	if len(resp.Members) != 2 {
		t.Fatalf("expected 2 members, got %d", len(resp.Members))
	}
	if resp.Members[0].Subject != "alice" {
		t.Fatalf("expected alice first, got %+v", resp.Members)
	}
	if got := resp.Members[0].Roles; len(got) != 2 || got[0] != "platform_admin" || got[1] != "platform_manager" {
		t.Fatalf("expected alice roles [platform_admin platform_manager], got %v", got)
	}
	if resp.Members[1].Subject != "root" {
		t.Fatalf("expected root second, got %+v", resp.Members)
	}
	if got := resp.Members[1].Roles; len(got) != 1 || got[0] != "platform_admin" {
		t.Fatalf("expected root roles [platform_admin], got %v", got)
	}
}

func TestAssignPlatformRole_DelegationBoundaries(t *testing.T) {
	env := setup(t)

	setupPlatformAdmin(t, env, "root")
	setupPlatformManager(t, env, "manager")

	assignManagerReq := reqWithSubjectJSON(
		http.MethodPost,
		"/admin/platform/members/bob/roles",
		"manager",
		assignRoleRequest{Role: "platform_manager"},
	)
	assignManagerResp := httptest.NewRecorder()
	env.mux.ServeHTTP(assignManagerResp, assignManagerReq)

	if assignManagerResp.Code != http.StatusNoContent {
		t.Fatalf("expected 204 when manager assigns manager role, got %d: %s", assignManagerResp.Code, assignManagerResp.Body.String())
	}

	roles, err := env.engine.ListSubjectRoles(context.Background(), "bob", "platform", "")
	must(t, err)
	if len(roles) != 1 || roles[0] != "platform_manager" {
		t.Fatalf("expected bob to have [platform_manager], got %v", roles)
	}

	assignAdminReq := reqWithSubjectJSON(
		http.MethodPost,
		"/admin/platform/members/carol/roles",
		"manager",
		assignRoleRequest{Role: "platform_admin"},
	)
	assignAdminResp := httptest.NewRecorder()
	env.mux.ServeHTTP(assignAdminResp, assignAdminReq)

	if assignAdminResp.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when manager assigns admin role, got %d: %s", assignAdminResp.Code, assignAdminResp.Body.String())
	}
}

func TestRevokePlatformRole_PreventsLastAdminRemoval(t *testing.T) {
	env := setup(t)

	setupPlatformAdmin(t, env, "root")

	r := reqWithSubject(http.MethodDelete, "/admin/platform/members/root/roles/platform_admin", "root")
	w := httptest.NewRecorder()
	env.mux.ServeHTTP(w, r)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}

	roles, err := env.engine.ListSubjectRoles(context.Background(), "root", "platform", "")
	must(t, err)
	if len(roles) != 1 || roles[0] != "platform_admin" {
		t.Fatalf("expected root to retain [platform_admin], got %v", roles)
	}
}

func TestRevokePlatformRole_RecordsAudit(t *testing.T) {
	env := setup(t)
	recorder := &captureAuditRecorder{}
	env.handler.auditRecorder = recorder

	setupPlatformAdmin(t, env, "root")
	setupPlatformAdmin(t, env, "alice")

	r := reqWithSubject(http.MethodDelete, "/admin/platform/members/alice/roles/platform_admin", "root")
	w := httptest.NewRecorder()
	env.mux.ServeHTTP(w, r)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}

	if len(recorder.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(recorder.events))
	}
	event := recorder.events[0]
	if event.Action != "role.revoke" {
		t.Fatalf("expected action role.revoke, got %q", event.Action)
	}
	if event.TargetID != "alice/platform_admin" {
		t.Fatalf("expected target alice/platform_admin, got %q", event.TargetID)
	}
	if event.ScopeType != "platform" || event.ScopeID != "" {
		t.Fatalf("expected platform scope, got %q/%q", event.ScopeType, event.ScopeID)
	}
}
