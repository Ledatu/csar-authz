package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ledatu/csar-authz/internal/store"
	"github.com/ledatu/csar-core/authzconfig"
)

func TestAssignRole_HTTPRejectsInvalidAdminScope(t *testing.T) {
	env := setup(t)
	setupWildcardPlatformAdmin(t, env, "root")
	must(t, env.store.CreateRole(context.Background(), &store.Role{Name: "tenant_admin"}))
	env.handler.SetConfig(&authzconfig.AdminConfig{ServiceAssignableRoles: []string{"tenant_admin", "platform_admin"}})

	requests := []*http.Request{
		reqWithSubjectJSON("POST", "/admin/tenants/wildberries:seller/members/target/roles", "root", assignRoleRequest{Role: "platform_admin"}),
		reqWithSubjectJSON("POST", "/admin/tenants/legacy-id/members/target/roles", "root", assignRoleRequest{Role: "tenant_admin"}),
		reqSvcAssignRole("wildberries:seller", "target", "platform_admin"),
		reqSvcAssignRole("wildberries:*", "target", "tenant_admin"),
	}
	for _, r := range requests {
		w := httptest.NewRecorder()
		env.mux.ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: expected 400, got %d: %s", r.URL.Path, w.Code, w.Body.String())
		}
	}
	grants, err := env.store.ListSubjectAssignments(context.Background(), "target")
	must(t, err)
	if len(grants) != 0 {
		t.Fatalf("invalid assignments persisted: %v", grants)
	}
}

func TestAssignRole_HTTPAcceptsTenantAdminAndLegacyRevocation(t *testing.T) {
	env := setup(t)
	setupWildcardPlatformAdmin(t, env, "root")
	ctx := context.Background()
	must(t, env.store.CreateRole(ctx, &store.Role{Name: "tenant_admin"}))
	must(t, env.store.AssignRole(ctx, "target", "tenant_admin", "tenant", "legacy-id"))
	env.handler.SetConfig(&authzconfig.AdminConfig{ServiceAssignableRoles: []string{"tenant_admin"}})
	for _, r := range []*http.Request{
		reqWithSubjectJSON("POST", "/admin/tenants/wildberries:seller/members/target/roles", "root", assignRoleRequest{Role: "tenant_admin"}),
		reqSvcAssignRole("ozon:123", "target", "tenant_admin"),
		reqSvcRevokeRole("legacy-id", "target", "tenant_admin"),
	} {
		w := httptest.NewRecorder()
		env.mux.ServeHTTP(w, r)
		if w.Code != http.StatusNoContent {
			t.Fatalf("%s: expected 204, got %d: %s", r.URL.Path, w.Code, w.Body.String())
		}
	}
}
