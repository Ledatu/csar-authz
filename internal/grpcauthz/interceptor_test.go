package grpcauthz

import (
	"context"
	"testing"

	"github.com/ledatu/csar-authz/internal/engine"
	"github.com/ledatu/csar-authz/internal/store"
	"github.com/ledatu/csar-authz/internal/store/memory"
	"github.com/ledatu/csar-core/authzconfig"
	"github.com/ledatu/csar-core/grpcjwt"
	pb "github.com/ledatu/csar-proto/csar/authz/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// testEnv bundles an in-memory store, engine, and interceptor for tests.
type testEnv struct {
	store       store.Store
	engine      *engine.Engine
	interceptor *Interceptor
}

func setup(t *testing.T, authnEnabled bool, delegatableRoles []string) *testEnv {
	t.Helper()
	s := memory.New()
	eng := engine.New(s)
	cfg := &authzconfig.AdminConfig{
		DelegatableRoles: delegatableRoles,
	}
	i := NewInterceptor(eng, cfg, authnEnabled)
	return &testEnv{store: s, engine: eng, interceptor: i}
}

// withSubject puts a JWT subject into context (mirrors grpcjwt internals).
func withSubject(ctx context.Context, subject string) context.Context {
	return grpcjwt.TestContextWithSubject(ctx, subject)
}

// call invokes the interceptor with the given method, request, and context.
// The inner handler returns the request as-is for assertion convenience.
func call(i *Interceptor, ctx context.Context, method string, req any) (any, error) {
	info := &grpc.UnaryServerInfo{FullMethod: method}
	handler := func(ctx context.Context, req any) (any, error) {
		return req, nil
	}
	return i.UnaryInterceptor()(ctx, req, info, handler)
}

// setupPlatformAdmin creates a platform_admin role with full permissions and
// assigns it to the given subject.
func setupPlatformAdmin(t *testing.T, env *testEnv, subject string) {
	t.Helper()
	ctx := context.Background()
	must(t, env.store.CreateRole(ctx, &store.Role{Name: "platform_admin"}))
	must(t, env.store.AddPermission(ctx, &store.Permission{Role: "platform_admin", Resource: "**", Action: "*"}))
	must(t, env.store.AssignRole(ctx, subject, "platform_admin", "platform", ""))
}

// setupTenantAdmin creates a tenant_admin role with tenant member management
// permissions and assigns it to the given subject in the given tenant.
func setupTenantAdmin(t *testing.T, env *testEnv, subject, tenantID string) {
	t.Helper()
	ctx := context.Background()
	_ = env.store.CreateRole(ctx, &store.Role{Name: "tenant_admin"})
	must(t, env.store.AddPermission(ctx, &store.Permission{Role: "tenant_admin", Resource: "admin", Action: "tenant.members.assign_role"}))
	must(t, env.store.AddPermission(ctx, &store.Permission{Role: "tenant_admin", Resource: "admin", Action: "tenant.members.revoke_role"}))
	must(t, env.store.AddPermission(ctx, &store.Permission{Role: "tenant_admin", Resource: "admin", Action: "tenant.members.read"}))
	must(t, env.store.AssignRole(ctx, subject, "tenant_admin", "tenant", tenantID))
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func assertCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if got := status.Code(err); got != want {
		t.Errorf("expected %v, got %v (err: %v)", want, got, err)
	}
}

// ── CheckAccess passthrough ─────────────────────────────────────────────────

func TestCheckAccess_AlwaysPassesThrough(t *testing.T) {
	env := setup(t, true, nil)
	resp, err := call(env.interceptor, context.Background(), servicePath+"CheckAccess", &pb.CheckAccessRequest{})
	if err != nil {
		t.Fatalf("expected pass-through, got %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

// ── Unauthenticated / dev-mode ──────────────────────────────────────────────

func TestCreateRole_NoSubject_AuthnEnabled_Unauthenticated(t *testing.T) {
	env := setup(t, true, nil)
	_, err := call(env.interceptor, context.Background(), servicePath+"CreateRole", &pb.CreateRoleRequest{Name: "x"})
	assertCode(t, err, codes.Unauthenticated)
}

func TestCreateRole_NoSubject_AuthnDisabled_PassesThrough(t *testing.T) {
	env := setup(t, false, nil)
	_, err := call(env.interceptor, context.Background(), servicePath+"CreateRole", &pb.CreateRoleRequest{Name: "x"})
	if err != nil {
		t.Fatalf("dev mode should pass through, got %v", err)
	}
}

// ── Permission denied ───────────────────────────────────────────────────────

func TestCreateRole_UnauthorizedSubject_PermissionDenied(t *testing.T) {
	env := setup(t, true, nil)
	ctx := withSubject(context.Background(), "nobody")
	_, err := call(env.interceptor, ctx, servicePath+"CreateRole", &pb.CreateRoleRequest{Name: "x"})
	assertCode(t, err, codes.PermissionDenied)
}

// ── Platform admin allowed ──────────────────────────────────────────────────

func TestCreateRole_PlatformAdmin_Allowed(t *testing.T) {
	env := setup(t, true, nil)
	setupPlatformAdmin(t, env, "admin-1")
	ctx := withSubject(context.Background(), "admin-1")
	_, err := call(env.interceptor, ctx, servicePath+"CreateRole", &pb.CreateRoleRequest{Name: "x"})
	if err != nil {
		t.Fatalf("platform admin should be allowed, got %v", err)
	}
}

func TestDeleteRole_PlatformAdmin_Allowed(t *testing.T) {
	env := setup(t, true, nil)
	setupPlatformAdmin(t, env, "admin-1")
	ctx := withSubject(context.Background(), "admin-1")
	_, err := call(env.interceptor, ctx, servicePath+"DeleteRole", &pb.DeleteRoleRequest{Name: "x"})
	if err != nil {
		t.Fatalf("platform admin should be allowed, got %v", err)
	}
}

func TestListRoles_PlatformAdmin_Allowed(t *testing.T) {
	env := setup(t, true, nil)
	setupPlatformAdmin(t, env, "admin-1")
	ctx := withSubject(context.Background(), "admin-1")
	_, err := call(env.interceptor, ctx, servicePath+"ListRoles", &pb.ListRolesRequest{})
	if err != nil {
		t.Fatalf("platform admin should be allowed, got %v", err)
	}
}

// ── Tenant-scoped assignment checks ─────────────────────────────────────────

func TestAssignRole_TenantScope_RequiresPermission(t *testing.T) {
	env := setup(t, true, nil)
	ctx := withSubject(context.Background(), "nobody")
	_, err := call(env.interceptor, ctx, servicePath+"AssignRole", &pb.AssignRoleRequest{
		Subject: "u1", Role: "viewer", ScopeType: "tenant", ScopeId: "t-1",
	})
	assertCode(t, err, codes.PermissionDenied)
}

func TestAssignRole_TenantAdmin_DelegatableRole_Allowed(t *testing.T) {
	env := setup(t, true, []string{"viewer"})
	setupTenantAdmin(t, env, "ta-1", "t-1")
	must(t, env.store.CreateRole(context.Background(), &store.Role{Name: "viewer"}))

	ctx := withSubject(context.Background(), "ta-1")
	_, err := call(env.interceptor, ctx, servicePath+"AssignRole", &pb.AssignRoleRequest{
		Subject: "u1", Role: "viewer", ScopeType: "tenant", ScopeId: "t-1",
	})
	if err != nil {
		t.Fatalf("tenant admin should be allowed to assign delegatable role, got %v", err)
	}
}

func TestAssignRole_TenantAdmin_NonDelegatableRole_Denied(t *testing.T) {
	env := setup(t, true, []string{"viewer"})
	setupTenantAdmin(t, env, "ta-1", "t-1")
	must(t, env.store.CreateRole(context.Background(), &store.Role{Name: "superadmin"}))

	ctx := withSubject(context.Background(), "ta-1")
	_, err := call(env.interceptor, ctx, servicePath+"AssignRole", &pb.AssignRoleRequest{
		Subject: "u1", Role: "superadmin", ScopeType: "tenant", ScopeId: "t-1",
	})
	assertCode(t, err, codes.PermissionDenied)
}

func TestAssignRole_PlatformAdmin_BypassesDelegation(t *testing.T) {
	env := setup(t, true, []string{"viewer"})
	setupPlatformAdmin(t, env, "pa-1")
	must(t, env.store.CreateRole(context.Background(), &store.Role{Name: "superadmin"}))

	ctx := withSubject(context.Background(), "pa-1")
	_, err := call(env.interceptor, ctx, servicePath+"AssignRole", &pb.AssignRoleRequest{
		Subject: "u1", Role: "superadmin", ScopeType: "tenant", ScopeId: "t-1",
	})
	if err != nil {
		t.Fatalf("platform admin should bypass delegation, got %v", err)
	}
}

// ── RevokeRole ──────────────────────────────────────────────────────────────

func TestRevokeRole_TenantAdmin_Allowed(t *testing.T) {
	env := setup(t, true, nil)
	setupTenantAdmin(t, env, "ta-1", "t-1")

	ctx := withSubject(context.Background(), "ta-1")
	_, err := call(env.interceptor, ctx, servicePath+"RevokeRole", &pb.RevokeRoleRequest{
		Subject: "u1", Role: "viewer", ScopeType: "tenant", ScopeId: "t-1",
	})
	if err != nil {
		t.Fatalf("tenant admin should be allowed to revoke, got %v", err)
	}
}

func TestRevokeRole_NoPermission_Denied(t *testing.T) {
	env := setup(t, true, nil)
	ctx := withSubject(context.Background(), "nobody")
	_, err := call(env.interceptor, ctx, servicePath+"RevokeRole", &pb.RevokeRoleRequest{
		Subject: "u1", Role: "viewer", ScopeType: "tenant", ScopeId: "t-1",
	})
	assertCode(t, err, codes.PermissionDenied)
}

// ── Sensitive reads ─────────────────────────────────────────────────────────

func TestListScopeAssignments_RequiresPermission(t *testing.T) {
	env := setup(t, true, nil)
	ctx := withSubject(context.Background(), "nobody")
	_, err := call(env.interceptor, ctx, servicePath+"ListScopeAssignments", &pb.ListScopeAssignmentsRequest{
		ScopeType: "tenant", ScopeId: "t-1",
	})
	assertCode(t, err, codes.PermissionDenied)
}

func TestListScopeAssignments_TenantAdmin_Allowed(t *testing.T) {
	env := setup(t, true, nil)
	setupTenantAdmin(t, env, "ta-1", "t-1")
	ctx := withSubject(context.Background(), "ta-1")
	_, err := call(env.interceptor, ctx, servicePath+"ListScopeAssignments", &pb.ListScopeAssignmentsRequest{
		ScopeType: "tenant", ScopeId: "t-1",
	})
	if err != nil {
		t.Fatalf("tenant admin should be allowed to list members, got %v", err)
	}
}

func TestListSubjectRoles_TenantScope_RequiresPermission(t *testing.T) {
	env := setup(t, true, nil)
	ctx := withSubject(context.Background(), "nobody")
	_, err := call(env.interceptor, ctx, servicePath+"ListSubjectRoles", &pb.ListSubjectRolesRequest{
		Subject: "u1", ScopeType: "tenant", ScopeId: "t-1",
	})
	assertCode(t, err, codes.PermissionDenied)
}

func TestListSubjectScopes_RequiresPlatformRead(t *testing.T) {
	env := setup(t, true, nil)
	ctx := withSubject(context.Background(), "nobody")
	_, err := call(env.interceptor, ctx, servicePath+"ListSubjectScopes", &pb.ListSubjectScopesRequest{
		Subject: "u1",
	})
	assertCode(t, err, codes.PermissionDenied)
}

func TestListSubjectScopes_PlatformAdmin_Allowed(t *testing.T) {
	env := setup(t, true, nil)
	setupPlatformAdmin(t, env, "admin-1")
	ctx := withSubject(context.Background(), "admin-1")
	_, err := call(env.interceptor, ctx, servicePath+"ListSubjectScopes", &pb.ListSubjectScopesRequest{
		Subject: "u1",
	})
	if err != nil {
		t.Fatalf("platform admin should be allowed, got %v", err)
	}
}

// ── Platform-scoped AssignRole (no delegation enforcement) ──────────────────

func TestAssignRole_PlatformScope_NoDelegationCheck(t *testing.T) {
	env := setup(t, true, nil)
	setupPlatformAdmin(t, env, "pa-1")

	ctx := withSubject(context.Background(), "pa-1")
	_, err := call(env.interceptor, ctx, servicePath+"AssignRole", &pb.AssignRoleRequest{
		Subject: "u1", Role: "anything", ScopeType: "platform",
	})
	if err != nil {
		t.Fatalf("platform-scoped assign should skip delegation, got %v", err)
	}
}

// ── Unmapped RPC fail-closed ─────────────────────────────────────────────────

func TestUnmappedRPC_Denied(t *testing.T) {
	env := setup(t, true, nil)
	setupPlatformAdmin(t, env, "admin-1")
	ctx := withSubject(context.Background(), "admin-1")

	_, err := call(env.interceptor, ctx, servicePath+"SomeNewRPC", nil)
	assertCode(t, err, codes.PermissionDenied)
}

// ── SetConfig hot-reload ────────────────────────────────────────────────────

func TestSetConfig_UpdatesDelegatableRoles(t *testing.T) {
	env := setup(t, true, []string{"viewer"})
	setupTenantAdmin(t, env, "ta-1", "t-1")
	must(t, env.store.CreateRole(context.Background(), &store.Role{Name: "editor"}))

	ctx := withSubject(context.Background(), "ta-1")

	// editor is not delegatable initially.
	_, err := call(env.interceptor, ctx, servicePath+"AssignRole", &pb.AssignRoleRequest{
		Subject: "u1", Role: "editor", ScopeType: "tenant", ScopeId: "t-1",
	})
	assertCode(t, err, codes.PermissionDenied)

	// Hot-reload config to make editor delegatable.
	env.interceptor.SetConfig(&authzconfig.AdminConfig{
		DelegatableRoles: []string{"viewer", "editor"},
	})

	_, err = call(env.interceptor, ctx, servicePath+"AssignRole", &pb.AssignRoleRequest{
		Subject: "u1", Role: "editor", ScopeType: "tenant", ScopeId: "t-1",
	})
	if err != nil {
		t.Fatalf("editor should be delegatable after config reload, got %v", err)
	}
}
