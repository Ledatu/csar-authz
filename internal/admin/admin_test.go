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
	return setupWithStore(t, s, s)
}

func setupWithStore(t *testing.T, backing *memory.Store, storage store.Store) *testEnv {
	t.Helper()
	eng := engine.New(storage)
	cfg := &authzconfig.AdminConfig{}
	h := New(eng, nil, nil, slog.Default(), cfg)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return &testEnv{store: backing, engine: eng, handler: h, mux: mux}
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

func roleByName(t *testing.T, roles []roleResponse, name string) roleResponse {
	t.Helper()
	for _, role := range roles {
		if role.Name == name {
			return role
		}
	}

	t.Fatalf("expected role %q in response", name)
	return roleResponse{}
}

type countingStore struct {
	*memory.Store

	listRolesCalls               int
	listRoleClosureCalls         int
	getRoleCalls                 int
	getSubjectRolesCalls         int
	listSubjectScopesCalls       int
	getRolePermissionsCalls      int
	listSubjectAssignmentsCall   int
	listPermissionsForRolesCalls int
}

func (s *countingStore) ListRoles(ctx context.Context) ([]*store.Role, error) {
	s.listRolesCalls++
	return s.Store.ListRoles(ctx)
}

func (s *countingStore) ListRoleClosure(ctx context.Context, roles []string) (map[string][]string, error) {
	s.listRoleClosureCalls++
	return s.Store.ListRoleClosure(ctx, roles)
}

func (s *countingStore) GetRole(ctx context.Context, name string) (*store.Role, error) {
	s.getRoleCalls++
	return s.Store.GetRole(ctx, name)
}

func (s *countingStore) GetSubjectRoles(ctx context.Context, subject, scopeType, scopeID string) ([]string, error) {
	s.getSubjectRolesCalls++
	return s.Store.GetSubjectRoles(ctx, subject, scopeType, scopeID)
}

func (s *countingStore) ListSubjectScopes(ctx context.Context, subject string) ([]store.SubjectScope, error) {
	s.listSubjectScopesCalls++
	return s.Store.ListSubjectScopes(ctx, subject)
}

func (s *countingStore) GetRolePermissions(ctx context.Context, role string) ([]*store.Permission, error) {
	s.getRolePermissionsCalls++
	return s.Store.GetRolePermissions(ctx, role)
}

func (s *countingStore) ListSubjectAssignments(ctx context.Context, subject string) ([]store.ScopedAssignment, error) {
	s.listSubjectAssignmentsCall++
	return s.Store.ListSubjectAssignments(ctx, subject)
}

func (s *countingStore) ListPermissionsForRoles(ctx context.Context, roles []string) (map[string][]*store.Permission, error) {
	s.listPermissionsForRolesCalls++
	return s.Store.ListPermissionsForRoles(ctx, roles)
}

func setupPlatformAdmin(t *testing.T, env *testEnv, subject string) {
	t.Helper()
	ctx := context.Background()
	_ = env.store.CreateRole(ctx, &store.Role{Name: "platform_admin"})
	must(t, env.store.AddPermission(ctx, &store.Permission{Role: "platform_admin", Resource: "admin", Action: "platform.roles.read"}))
	must(t, env.store.AddPermission(ctx, &store.Permission{Role: "platform_admin", Resource: "admin", Action: "platform.roles.create"}))
	must(t, env.store.AddPermission(ctx, &store.Permission{Role: "platform_admin", Resource: "admin", Action: "platform.roles.delete"}))
	must(t, env.store.AddPermission(ctx, &store.Permission{Role: "platform_admin", Resource: "admin", Action: "platform.roles.assign"}))
	must(t, env.store.AddPermission(ctx, &store.Permission{Role: "platform_admin", Resource: "admin", Action: "platform.roles.revoke"}))
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

func setupPlatformManager(t *testing.T, env *testEnv, subject string) {
	t.Helper()
	ctx := context.Background()
	_ = env.store.CreateRole(ctx, &store.Role{Name: "platform_manager"})
	must(t, env.store.AddPermission(ctx, &store.Permission{Role: "platform_manager", Resource: "admin", Action: "platform.roles.read"}))
	must(t, env.store.AddPermission(ctx, &store.Permission{Role: "platform_manager", Resource: "admin", Action: "platform.roles.assign"}))
	must(t, env.store.AddPermission(ctx, &store.Permission{Role: "platform_manager", Resource: "admin", Action: "platform.roles.revoke"}))
	must(t, env.store.AssignRole(ctx, subject, "platform_manager", "platform", ""))
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

	var resp []roleResponse
	must(t, json.NewDecoder(w.Body).Decode(&resp))

	role := roleByName(t, resp, "tenant_admin")
	if len(role.Permissions) == 0 {
		t.Fatal("expected tenant_admin permissions in role list payload")
	}

	actions := make(map[string]struct{}, len(role.Permissions))
	for _, perm := range role.Permissions {
		actions[perm.Action] = struct{}{}
	}
	if _, ok := actions["tenant.roles.read"]; !ok {
		t.Fatal("expected tenant.roles.read permission in role list payload")
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

	var resp []roleResponse
	must(t, json.NewDecoder(w.Body).Decode(&resp))

	role := roleByName(t, resp, "platform_admin")
	if len(role.Permissions) == 0 {
		t.Fatal("expected platform_admin permissions in role list payload")
	}

	actions := make(map[string]struct{}, len(role.Permissions))
	for _, perm := range role.Permissions {
		actions[perm.Action] = struct{}{}
	}
	if _, ok := actions["platform.roles.read"]; !ok {
		t.Fatal("expected platform.roles.read permission in role list payload")
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

func TestCapabilities_UsesBulkLookupPaths(t *testing.T) {
	backing := memory.New()
	counting := &countingStore{Store: backing}
	env := setupWithStore(t, backing, counting)
	ctx := context.Background()

	setupPlatformAdmin(t, env, "root")
	must(t, env.store.CreateRole(ctx, &store.Role{Name: "tenant_admin", Parents: []string{"platform_admin"}}))
	must(t, env.store.AddPermission(ctx, &store.Permission{Role: "tenant_admin", Resource: "admin", Action: "tenant.members.read"}))
	must(t, env.store.AssignRole(ctx, "root", "tenant_admin", "tenant", "acme"))

	r := reqWithSubject("GET", "/admin/me/capabilities", "root")
	w := httptest.NewRecorder()
	env.mux.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if counting.listSubjectAssignmentsCall == 0 {
		t.Fatal("expected bulk subject assignment lookup")
	}
	if counting.listPermissionsForRolesCalls == 0 {
		t.Fatal("expected bulk permissions lookup")
	}
	if counting.listRoleClosureCalls == 0 {
		t.Fatal("expected shared role-closure lookup")
	}
	if counting.listRolesCalls != 0 {
		t.Fatalf("expected no full role catalog reads, got %d", counting.listRolesCalls)
	}
	if counting.getRoleCalls != 0 {
		t.Fatalf("expected no per-role reads, got %d", counting.getRoleCalls)
	}
	if counting.getSubjectRolesCalls != 0 {
		t.Fatalf("expected no per-scope role lookups, got %d", counting.getSubjectRolesCalls)
	}
	if counting.listSubjectScopesCalls != 0 {
		t.Fatalf("expected no subject scope lookups, got %d", counting.listSubjectScopesCalls)
	}
	if counting.getRolePermissionsCalls != 0 {
		t.Fatalf("expected no per-role permission lookups, got %d", counting.getRolePermissionsCalls)
	}
}

func TestCapabilities_NoAssignments_SkipsRoleCatalogRead(t *testing.T) {
	backing := memory.New()
	counting := &countingStore{Store: backing}
	env := setupWithStore(t, backing, counting)

	r := reqWithSubject("GET", "/admin/me/capabilities", "nobody")
	w := httptest.NewRecorder()
	env.mux.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if counting.listSubjectAssignmentsCall != 1 {
		t.Fatalf("expected one assignment lookup, got %d", counting.listSubjectAssignmentsCall)
	}
	if counting.listRolesCalls != 0 {
		t.Fatalf("expected no role catalog reads, got %d", counting.listRolesCalls)
	}
	if counting.listPermissionsForRolesCalls != 0 {
		t.Fatalf("expected no bulk permission reads, got %d", counting.listPermissionsForRolesCalls)
	}
	if counting.listRoleClosureCalls != 0 {
		t.Fatalf("expected no role-closure lookups, got %d", counting.listRoleClosureCalls)
	}
}

func TestCapabilities_NonAdminAssignment_SkipsRoleCatalogRead(t *testing.T) {
	backing := memory.New()
	counting := &countingStore{Store: backing}
	env := setupWithStore(t, backing, counting)
	ctx := context.Background()

	must(t, env.store.CreateRole(ctx, &store.Role{Name: "viewer"}))
	must(t, env.store.AddPermission(ctx, &store.Permission{Role: "viewer", Resource: "/wb/**", Action: "GET"}))
	must(t, env.store.AssignRole(ctx, "alice", "viewer", "platform", ""))

	r := reqWithSubject("GET", "/admin/me/capabilities", "alice")
	w := httptest.NewRecorder()
	env.mux.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if counting.listSubjectAssignmentsCall != 1 {
		t.Fatalf("expected one assignment lookup, got %d", counting.listSubjectAssignmentsCall)
	}
	if counting.listRolesCalls != 0 {
		t.Fatalf("expected no role catalog reads, got %d", counting.listRolesCalls)
	}
	if counting.listRoleClosureCalls != 1 {
		t.Fatalf("expected one role-closure lookup, got %d", counting.listRoleClosureCalls)
	}
	if counting.getRoleCalls != 0 {
		t.Fatalf("expected no per-role reads, got %d", counting.getRoleCalls)
	}
	if counting.listPermissionsForRolesCalls != 1 {
		t.Fatalf("expected one bulk permission lookup, got %d", counting.listPermissionsForRolesCalls)
	}

	var resp capabilitiesResponse
	must(t, json.NewDecoder(w.Body).Decode(&resp))
	if resp.PlatformAdmin {
		t.Fatal("expected non-admin subject to stay non-platform-admin")
	}
	if len(resp.PlatformCapabilities) != 0 {
		t.Fatalf("expected empty platform capabilities, got %v", resp.PlatformCapabilities)
	}
	if len(resp.TenantCapabilities) != 0 {
		t.Fatalf("expected no tenant capabilities, got %v", resp.TenantCapabilities)
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

func TestListRoles_UsesBulkPermissionLookup(t *testing.T) {
	backing := memory.New()
	counting := &countingStore{Store: backing}
	env := setupWithStore(t, backing, counting)

	setupPlatformAdmin(t, env, "root")
	r := reqWithSubject("GET", "/admin/roles", "root")
	w := httptest.NewRecorder()
	env.mux.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if counting.listPermissionsForRolesCalls == 0 {
		t.Fatal("expected bulk permissions lookup")
	}
	if counting.listPermissionsForRolesCalls != 2 {
		t.Fatalf("expected auth check and handler to use bulk permission lookups, got %d", counting.listPermissionsForRolesCalls)
	}
	if counting.listRoleClosureCalls != 1 {
		t.Fatalf("expected auth check to use one role-closure lookup, got %d", counting.listRoleClosureCalls)
	}
	if counting.getRolePermissionsCalls != 0 {
		t.Fatalf("expected no per-role permission lookups, got %d", counting.getRolePermissionsCalls)
	}
}
