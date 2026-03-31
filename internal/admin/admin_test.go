package admin

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ledatu/csar-authz/internal/engine"
	"github.com/ledatu/csar-authz/internal/store"
	"github.com/ledatu/csar-authz/internal/store/memory"
	"github.com/ledatu/csar-core/authzconfig"
	"github.com/ledatu/csar-core/gatewayctx"
)

type testEnv struct {
	store   *memory.Store
	engine  *engine.Engine
	handler *Handler
	mux     *http.ServeMux
}

func setup(t *testing.T) *testEnv {
	t.Helper()
	s := memory.New()
	eng := engine.New(s)
	cfg := &authzconfig.AdminConfig{}
	h := New(eng, nil, nil, slog.Default(), cfg)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return &testEnv{store: s, engine: eng, handler: h, mux: mux}
}

func reqWithSubject(method, path, subject string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	ctx := gatewayctx.NewContext(r.Context(), &gatewayctx.Identity{Subject: subject})
	return r.WithContext(ctx)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func setupPlatformAdmin(t *testing.T, env *testEnv, subject string) {
	t.Helper()
	ctx := context.Background()
	must(t, env.store.CreateRole(ctx, &store.Role{Name: "platform_admin"}))
	must(t, env.store.AddPermission(ctx, &store.Permission{Role: "platform_admin", Resource: "admin", Action: "platform.roles.read"}))
	must(t, env.store.AddPermission(ctx, &store.Permission{Role: "platform_admin", Resource: "admin", Action: "platform.roles.create"}))
	must(t, env.store.AddPermission(ctx, &store.Permission{Role: "platform_admin", Resource: "admin", Action: "platform.roles.delete"}))
	must(t, env.store.AssignRole(ctx, subject, "platform_admin", "platform", ""))
}

func setupWildcardPlatformAdmin(t *testing.T, env *testEnv, subject string) {
	t.Helper()
	ctx := context.Background()
	must(t, env.store.CreateRole(ctx, &store.Role{Name: "platform_admin"}))
	must(t, env.store.AddPermission(ctx, &store.Permission{Role: "platform_admin", Resource: "**", Action: "*"}))
	must(t, env.store.AssignRole(ctx, subject, "platform_admin", "platform", ""))
}

func setupTenantAdmin(t *testing.T, env *testEnv, subject, tenantID string) {
	t.Helper()
	ctx := context.Background()
	// Create role only if it doesn't exist yet.
	_ = env.store.CreateRole(ctx, &store.Role{Name: "tenant_admin"})
	must(t, env.store.AddPermission(ctx, &store.Permission{Role: "tenant_admin", Resource: "admin", Action: "tenant.roles.read"}))
	must(t, env.store.AddPermission(ctx, &store.Permission{Role: "tenant_admin", Resource: "admin", Action: "tenant.members.read"}))
	must(t, env.store.AssignRole(ctx, subject, "tenant_admin", "tenant", tenantID))
}

// --- Bug A: tenant.roles.read scope fix ---

func TestListRoles_TenantAdmin_WithTenantID(t *testing.T) {
	env := setup(t)
	setupTenantAdmin(t, env, "alice", "acme")

	r := reqWithSubject("GET", "/admin/roles?tenant_id=acme", "alice")
	w := httptest.NewRecorder()
	env.mux.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestListRoles_TenantAdmin_WithoutTenantID_Denied(t *testing.T) {
	env := setup(t)
	setupTenantAdmin(t, env, "alice", "acme")

	r := reqWithSubject("GET", "/admin/roles", "alice")
	w := httptest.NewRecorder()
	env.mux.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestListRoles_TenantAdmin_WrongTenantID_Denied(t *testing.T) {
	env := setup(t)
	setupTenantAdmin(t, env, "alice", "acme")

	r := reqWithSubject("GET", "/admin/roles?tenant_id=other", "alice")
	w := httptest.NewRecorder()
	env.mux.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetRole_TenantAdmin_WithTenantID(t *testing.T) {
	env := setup(t)
	setupTenantAdmin(t, env, "alice", "acme")

	r := reqWithSubject("GET", "/admin/roles/tenant_admin?tenant_id=acme", "alice")
	w := httptest.NewRecorder()
	env.mux.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetRole_TenantAdmin_WithoutTenantID_Denied(t *testing.T) {
	env := setup(t)
	setupTenantAdmin(t, env, "alice", "acme")

	r := reqWithSubject("GET", "/admin/roles/tenant_admin", "alice")
	w := httptest.NewRecorder()
	env.mux.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestListRoles_PlatformAdmin_NoTenantIDNeeded(t *testing.T) {
	env := setup(t)
	setupPlatformAdmin(t, env, "root")

	r := reqWithSubject("GET", "/admin/roles", "root")
	w := httptest.NewRecorder()
	env.mux.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- Bug B: platform_admin flag in capabilities ---

func TestCapabilities_PlatformAdmin_Flag(t *testing.T) {
	env := setup(t)
	setupPlatformAdmin(t, env, "root")

	r := reqWithSubject("GET", "/admin/me/capabilities", "root")
	w := httptest.NewRecorder()
	env.mux.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp capabilitiesResponse
	must(t, json.NewDecoder(w.Body).Decode(&resp))

	if !resp.PlatformAdmin {
		t.Fatal("expected platform_admin=true for platform admin")
	}
	if len(resp.PlatformCapabilities) == 0 {
		t.Fatal("expected non-empty platform_capabilities")
	}
}

func TestCapabilities_TenantAdmin_NoPlatformFlag(t *testing.T) {
	env := setup(t)
	setupTenantAdmin(t, env, "alice", "acme")

	r := reqWithSubject("GET", "/admin/me/capabilities", "alice")
	w := httptest.NewRecorder()
	env.mux.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp capabilitiesResponse
	must(t, json.NewDecoder(w.Body).Decode(&resp))

	if resp.PlatformAdmin {
		t.Fatal("expected platform_admin=false for tenant admin")
	}
}

func TestCapabilities_WildcardPlatformAdmin_ExpandsCapabilities(t *testing.T) {
	env := setup(t)
	setupWildcardPlatformAdmin(t, env, "root")

	r := reqWithSubject("GET", "/admin/me/capabilities", "root")
	w := httptest.NewRecorder()
	env.mux.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp capabilitiesResponse
	must(t, json.NewDecoder(w.Body).Decode(&resp))

	if !resp.PlatformAdmin {
		t.Fatal("expected platform_admin=true for wildcard platform admin")
	}

	actions := make(map[string]struct{}, len(resp.PlatformCapabilities))
	for _, action := range resp.PlatformCapabilities {
		actions[action] = struct{}{}
	}
	if _, ok := actions["platform.roles.read"]; !ok {
		t.Fatal("expected wildcard capability expansion to include platform.roles.read")
	}
	if _, ok := actions["admin.audit.read"]; !ok {
		t.Fatal("expected wildcard capability expansion to include admin.audit.read")
	}
	if _, ok := actions["*"]; ok {
		t.Fatal("expected wildcard capability to expand to concrete actions")
	}
}

// --- Bug C: platform admin sees all tenants ---

func TestMyTenants_PlatformAdmin_SeesAllTenants(t *testing.T) {
	env := setup(t)
	ctx := context.Background()
	setupPlatformAdmin(t, env, "root")

	// Create a tenant_viewer role and assign a different user in two tenants.
	must(t, env.store.CreateRole(ctx, &store.Role{Name: "viewer"}))
	must(t, env.store.AssignRole(ctx, "bob", "viewer", "tenant", "acme"))
	must(t, env.store.AssignRole(ctx, "carol", "viewer", "tenant", "globex"))

	r := reqWithSubject("GET", "/admin/me/tenants", "root")
	w := httptest.NewRecorder()
	env.mux.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp myTenantsResponse
	must(t, json.NewDecoder(w.Body).Decode(&resp))

	tenantSet := make(map[string]struct{})
	for _, tid := range resp.Tenants {
		tenantSet[tid] = struct{}{}
	}
	if _, ok := tenantSet["acme"]; !ok {
		t.Error("expected tenant 'acme' in response")
	}
	if _, ok := tenantSet["globex"]; !ok {
		t.Error("expected tenant 'globex' in response")
	}
}

func TestMyTenants_TenantAdmin_OnlyOwnTenants(t *testing.T) {
	env := setup(t)
	ctx := context.Background()
	setupTenantAdmin(t, env, "alice", "acme")

	must(t, env.store.CreateRole(ctx, &store.Role{Name: "viewer"}))
	must(t, env.store.AssignRole(ctx, "bob", "viewer", "tenant", "globex"))

	r := reqWithSubject("GET", "/admin/me/tenants", "alice")
	w := httptest.NewRecorder()
	env.mux.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp myTenantsResponse
	must(t, json.NewDecoder(w.Body).Decode(&resp))

	if len(resp.Tenants) != 1 || resp.Tenants[0] != "acme" {
		t.Fatalf("expected [acme], got %v", resp.Tenants)
	}
}

func TestMyTenants_WildcardPlatformAdmin_SeesAllTenants(t *testing.T) {
	env := setup(t)
	ctx := context.Background()
	setupWildcardPlatformAdmin(t, env, "root")

	must(t, env.store.CreateRole(ctx, &store.Role{Name: "viewer"}))
	must(t, env.store.AssignRole(ctx, "bob", "viewer", "tenant", "acme"))
	must(t, env.store.AssignRole(ctx, "carol", "viewer", "tenant", "globex"))

	r := reqWithSubject("GET", "/admin/me/tenants", "root")
	w := httptest.NewRecorder()
	env.mux.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp myTenantsResponse
	must(t, json.NewDecoder(w.Body).Decode(&resp))

	tenantSet := make(map[string]struct{})
	for _, tid := range resp.Tenants {
		tenantSet[tid] = struct{}{}
	}
	if _, ok := tenantSet["acme"]; !ok {
		t.Error("expected tenant 'acme' in response")
	}
	if _, ok := tenantSet["globex"]; !ok {
		t.Error("expected tenant 'globex' in response")
	}
}

// --- Missing endpoint: GET /admin/roles/{role}/permissions ---

func TestListRolePermissions_PlatformAdmin(t *testing.T) {
	env := setup(t)
	setupPlatformAdmin(t, env, "root")

	r := reqWithSubject("GET", "/admin/roles/platform_admin/permissions", "root")
	w := httptest.NewRecorder()
	env.mux.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp []permissionResponse
	must(t, json.NewDecoder(w.Body).Decode(&resp))

	if len(resp) == 0 {
		t.Fatal("expected non-empty permissions list")
	}

	actions := make(map[string]struct{})
	for _, p := range resp {
		actions[p.Action] = struct{}{}
	}
	if _, ok := actions["platform.roles.read"]; !ok {
		t.Error("expected platform.roles.read permission")
	}
}

func TestListRolePermissions_TenantAdmin_WithTenantID(t *testing.T) {
	env := setup(t)
	setupTenantAdmin(t, env, "alice", "acme")

	r := reqWithSubject("GET", "/admin/roles/tenant_admin/permissions?tenant_id=acme", "alice")
	w := httptest.NewRecorder()
	env.mux.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestListRolePermissions_Unauthorized_Denied(t *testing.T) {
	env := setup(t)
	ctx := context.Background()
	must(t, env.store.CreateRole(ctx, &store.Role{Name: "viewer"}))

	r := reqWithSubject("GET", "/admin/roles/viewer/permissions", "nobody")
	w := httptest.NewRecorder()
	env.mux.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestListRolePermissions_Unauthenticated(t *testing.T) {
	env := setup(t)

	r := httptest.NewRequest("GET", "/admin/roles/viewer/permissions", nil)
	w := httptest.NewRecorder()
	env.mux.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}
