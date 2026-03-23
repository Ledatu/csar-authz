package server

import (
	"context"
	"testing"

	"github.com/ledatu/csar-authz/internal/engine"
	"github.com/ledatu/csar-authz/internal/store/memory"
	"github.com/ledatu/csar-core/gatewayctx"
	pb "github.com/ledatu/csar-proto/csar/authz/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func setupTestServer(t *testing.T) (*Server, context.Context) {
	t.Helper()
	s := memory.New()
	e := engine.New(s)
	srv := New(e)
	return srv, context.Background()
}

func TestCheckAccess_Validation(t *testing.T) {
	srv, ctx := setupTestServer(t)

	tests := []struct {
		name string
		req  *pb.CheckAccessRequest
	}{
		{"empty subject", &pb.CheckAccessRequest{Resource: "/api", Action: "GET", ScopeType: "platform"}},
		{"empty resource", &pb.CheckAccessRequest{Subject: "u1", Action: "GET", ScopeType: "platform"}},
		{"empty action", &pb.CheckAccessRequest{Subject: "u1", Resource: "/api", ScopeType: "platform"}},
		{"empty scope_type", &pb.CheckAccessRequest{Subject: "u1", Resource: "/api", Action: "GET"}},
		{"bad scope_type", &pb.CheckAccessRequest{Subject: "u1", Resource: "/api", Action: "GET", ScopeType: "org"}},
		{"tenant without scope_id", &pb.CheckAccessRequest{Subject: "u1", Resource: "/api", Action: "GET", ScopeType: "tenant"}},
	}

	for _, tt := range tests {
		_, err := srv.CheckAccess(ctx, tt.req)
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: expected InvalidArgument, got %v", tt.name, err)
		}
	}
}

func TestCheckAccess_Flow(t *testing.T) {
	srv, ctx := setupTestServer(t)

	_, err := srv.CreateRole(ctx, &pb.CreateRoleRequest{
		Name:        "viewer",
		Description: "Read-only access",
	})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}

	_, err = srv.AddPermission(ctx, &pb.AddPermissionRequest{
		Role:     "viewer",
		Resource: "/api/v1/**",
		Action:   "GET",
	})
	if err != nil {
		t.Fatalf("AddPermission: %v", err)
	}

	_, err = srv.AssignRole(ctx, &pb.AssignRoleRequest{
		Subject:   "user-1",
		Role:      "viewer",
		ScopeType: "platform",
	})
	if err != nil {
		t.Fatalf("AssignRole: %v", err)
	}

	// CheckAccess: allowed.
	resp, err := srv.CheckAccess(ctx, &pb.CheckAccessRequest{
		Subject:   "user-1",
		Resource:  "/api/v1/projects",
		Action:    "GET",
		ScopeType: "platform",
	})
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if !resp.Allowed {
		t.Error("expected allowed")
	}
	if resp.EnrichedHeaders["X-Authz-Decision"] != "allow" {
		t.Errorf("expected X-Authz-Decision=allow, got %q", resp.EnrichedHeaders["X-Authz-Decision"])
	}
	if resp.EnrichedHeaders[gatewayctx.HeaderSubject] != "user-1" {
		t.Errorf("expected %s=user-1, got %q", gatewayctx.HeaderSubject, resp.EnrichedHeaders[gatewayctx.HeaderSubject])
	}
	if resp.EnrichedHeaders[gatewayctx.HeaderAuthzResult] != "allow" {
		t.Errorf("expected %s=allow, got %q", gatewayctx.HeaderAuthzResult, resp.EnrichedHeaders[gatewayctx.HeaderAuthzResult])
	}

	// CheckAccess: denied (wrong action).
	resp, err = srv.CheckAccess(ctx, &pb.CheckAccessRequest{
		Subject:   "user-1",
		Resource:  "/api/v1/projects",
		Action:    "DELETE",
		ScopeType: "platform",
	})
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if resp.Allowed {
		t.Error("expected denied for DELETE")
	}

	// CheckAccess: denied (unknown user).
	resp, err = srv.CheckAccess(ctx, &pb.CheckAccessRequest{
		Subject:   "unknown-user",
		Resource:  "/api/v1/projects",
		Action:    "GET",
		ScopeType: "platform",
	})
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if resp.Allowed {
		t.Error("expected denied for unknown user")
	}
}

func TestCreateRole_Duplicate(t *testing.T) {
	srv, ctx := setupTestServer(t)

	_, _ = srv.CreateRole(ctx, &pb.CreateRoleRequest{Name: "admin"})
	_, err := srv.CreateRole(ctx, &pb.CreateRoleRequest{Name: "admin"})
	if status.Code(err) != codes.AlreadyExists {
		t.Errorf("expected AlreadyExists, got %v", err)
	}
}

func TestCreateRole_InvalidParent(t *testing.T) {
	srv, ctx := setupTestServer(t)

	_, err := srv.CreateRole(ctx, &pb.CreateRoleRequest{
		Name:    "editor",
		Parents: []string{"nonexistent"},
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("expected NotFound, got %v", err)
	}
}

func TestDeleteRole_NotFound(t *testing.T) {
	srv, ctx := setupTestServer(t)

	_, err := srv.DeleteRole(ctx, &pb.DeleteRoleRequest{Name: "nope"})
	if status.Code(err) != codes.NotFound {
		t.Errorf("expected NotFound, got %v", err)
	}
}

func TestGetRole(t *testing.T) {
	srv, ctx := setupTestServer(t)

	_, _ = srv.CreateRole(ctx, &pb.CreateRoleRequest{Name: "admin", Description: "Full access"})

	resp, err := srv.GetRole(ctx, &pb.GetRoleRequest{Name: "admin"})
	if err != nil {
		t.Fatalf("GetRole: %v", err)
	}
	if resp.Role.Name != "admin" || resp.Role.Description != "Full access" {
		t.Errorf("unexpected role: %+v", resp.Role)
	}
}

func TestListRoles(t *testing.T) {
	srv, ctx := setupTestServer(t)

	_, _ = srv.CreateRole(ctx, &pb.CreateRoleRequest{Name: "a"})
	_, _ = srv.CreateRole(ctx, &pb.CreateRoleRequest{Name: "b"})

	resp, err := srv.ListRoles(ctx, &pb.ListRolesRequest{})
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if len(resp.Roles) != 2 {
		t.Errorf("expected 2 roles, got %d", len(resp.Roles))
	}
}

func TestAssignRole_NotFound(t *testing.T) {
	srv, ctx := setupTestServer(t)

	_, err := srv.AssignRole(ctx, &pb.AssignRoleRequest{
		Subject:   "user-1",
		Role:      "nonexistent",
		ScopeType: "platform",
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("expected NotFound, got %v", err)
	}
}

func TestAssignRole_MissingScope(t *testing.T) {
	srv, ctx := setupTestServer(t)

	_, _ = srv.CreateRole(ctx, &pb.CreateRoleRequest{Name: "admin"})

	_, err := srv.AssignRole(ctx, &pb.AssignRoleRequest{
		Subject: "user-1",
		Role:    "admin",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument for missing scope_type, got %v", err)
	}
}

func TestListSubjectRoles(t *testing.T) {
	srv, ctx := setupTestServer(t)

	_, _ = srv.CreateRole(ctx, &pb.CreateRoleRequest{Name: "admin"})
	_, _ = srv.CreateRole(ctx, &pb.CreateRoleRequest{Name: "viewer"})
	_, _ = srv.AssignRole(ctx, &pb.AssignRoleRequest{Subject: "u1", Role: "admin", ScopeType: "platform"})
	_, _ = srv.AssignRole(ctx, &pb.AssignRoleRequest{Subject: "u1", Role: "viewer", ScopeType: "platform"})

	resp, err := srv.ListSubjectRoles(ctx, &pb.ListSubjectRolesRequest{Subject: "u1", ScopeType: "platform"})
	if err != nil {
		t.Fatalf("ListSubjectRoles: %v", err)
	}
	if len(resp.Roles) != 2 {
		t.Errorf("expected 2 roles, got %d: %v", len(resp.Roles), resp.Roles)
	}
}

func TestRevokeRole(t *testing.T) {
	srv, ctx := setupTestServer(t)

	_, _ = srv.CreateRole(ctx, &pb.CreateRoleRequest{Name: "admin"})
	_, _ = srv.AssignRole(ctx, &pb.AssignRoleRequest{Subject: "u1", Role: "admin", ScopeType: "platform"})
	_, err := srv.RevokeRole(ctx, &pb.RevokeRoleRequest{Subject: "u1", Role: "admin", ScopeType: "platform"})
	if err != nil {
		t.Fatalf("RevokeRole: %v", err)
	}

	resp, _ := srv.ListSubjectRoles(ctx, &pb.ListSubjectRolesRequest{Subject: "u1", ScopeType: "platform"})
	if len(resp.Roles) != 0 {
		t.Errorf("expected no roles after revoke, got %v", resp.Roles)
	}
}

func TestAddPermission_RoleNotFound(t *testing.T) {
	srv, ctx := setupTestServer(t)

	_, err := srv.AddPermission(ctx, &pb.AddPermissionRequest{
		Role:     "nonexistent",
		Resource: "/api",
		Action:   "GET",
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("expected NotFound, got %v", err)
	}
}

func TestRemovePermission(t *testing.T) {
	srv, ctx := setupTestServer(t)

	_, _ = srv.CreateRole(ctx, &pb.CreateRoleRequest{Name: "editor"})
	addResp, _ := srv.AddPermission(ctx, &pb.AddPermissionRequest{
		Role:     "editor",
		Resource: "/api",
		Action:   "PUT",
	})

	_, err := srv.RemovePermission(ctx, &pb.RemovePermissionRequest{Id: addResp.Permission.Id})
	if err != nil {
		t.Fatalf("RemovePermission: %v", err)
	}

	listResp, _ := srv.ListRolePermissions(ctx, &pb.ListRolePermissionsRequest{Role: "editor"})
	if len(listResp.Permissions) != 0 {
		t.Errorf("expected 0 permissions after removal, got %d", len(listResp.Permissions))
	}
}

func TestRemovePermission_NotFound(t *testing.T) {
	srv, ctx := setupTestServer(t)

	_, err := srv.RemovePermission(ctx, &pb.RemovePermissionRequest{Id: "nope"})
	if status.Code(err) != codes.NotFound {
		t.Errorf("expected NotFound, got %v", err)
	}
}

func TestListRolePermissions(t *testing.T) {
	srv, ctx := setupTestServer(t)

	_, _ = srv.CreateRole(ctx, &pb.CreateRoleRequest{Name: "editor"})
	_, _ = srv.AddPermission(ctx, &pb.AddPermissionRequest{Role: "editor", Resource: "/a", Action: "GET"})
	_, _ = srv.AddPermission(ctx, &pb.AddPermissionRequest{Role: "editor", Resource: "/b", Action: "POST"})

	resp, err := srv.ListRolePermissions(ctx, &pb.ListRolePermissionsRequest{Role: "editor"})
	if err != nil {
		t.Fatalf("ListRolePermissions: %v", err)
	}
	if len(resp.Permissions) != 2 {
		t.Errorf("expected 2 permissions, got %d", len(resp.Permissions))
	}
}

func TestCheckAccess_WithHierarchy(t *testing.T) {
	srv, ctx := setupTestServer(t)

	_, _ = srv.CreateRole(ctx, &pb.CreateRoleRequest{Name: "reader"})
	_, _ = srv.AddPermission(ctx, &pb.AddPermissionRequest{
		Role: "reader", Resource: "/api/**", Action: "GET",
	})

	_, _ = srv.CreateRole(ctx, &pb.CreateRoleRequest{
		Name: "editor", Parents: []string{"reader"},
	})
	_, _ = srv.AddPermission(ctx, &pb.AddPermissionRequest{
		Role: "editor", Resource: "/api/v1/posts/**", Action: "PUT",
	})

	_, _ = srv.AssignRole(ctx, &pb.AssignRoleRequest{Subject: "u1", Role: "editor", ScopeType: "platform"})

	resp, _ := srv.CheckAccess(ctx, &pb.CheckAccessRequest{
		Subject: "u1", Resource: "/api/v1/users", Action: "GET", ScopeType: "platform",
	})
	if !resp.Allowed {
		t.Error("expected GET allowed via inherited reader")
	}

	resp, _ = srv.CheckAccess(ctx, &pb.CheckAccessRequest{
		Subject: "u1", Resource: "/api/v1/posts/123", Action: "PUT", ScopeType: "platform",
	})
	if !resp.Allowed {
		t.Error("expected PUT allowed via editor")
	}

	resp, _ = srv.CheckAccess(ctx, &pb.CheckAccessRequest{
		Subject: "u1", Resource: "/api/v1/posts/123", Action: "DELETE", ScopeType: "platform",
	})
	if resp.Allowed {
		t.Error("expected DELETE denied")
	}
}

// --- Tenant-scoped server tests ---

func TestCheckAccess_TenantScoped(t *testing.T) {
	srv, ctx := setupTestServer(t)

	_, _ = srv.CreateRole(ctx, &pb.CreateRoleRequest{Name: "tenant_viewer"})
	_, _ = srv.AddPermission(ctx, &pb.AddPermissionRequest{
		Role: "tenant_viewer", Resource: "prices", Action: "read",
	})

	_, _ = srv.AssignRole(ctx, &pb.AssignRoleRequest{
		Subject:   "user-42",
		Role:      "tenant_viewer",
		ScopeType: "tenant",
		ScopeId:   "t-100",
	})

	resp, err := srv.CheckAccess(ctx, &pb.CheckAccessRequest{
		Subject:   "user-42",
		Resource:  "prices",
		Action:    "read",
		ScopeType: "tenant",
		ScopeId:   "t-100",
	})
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if !resp.Allowed {
		t.Error("expected allowed in tenant t-100")
	}

	resp, err = srv.CheckAccess(ctx, &pb.CheckAccessRequest{
		Subject:   "user-42",
		Resource:  "prices",
		Action:    "read",
		ScopeType: "tenant",
		ScopeId:   "t-200",
	})
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if resp.Allowed {
		t.Error("expected denied in t-200 (cross-tenant isolation)")
	}
}

func TestCheckAccess_PlatformFallbackInTenantScope(t *testing.T) {
	srv, ctx := setupTestServer(t)

	_, _ = srv.CreateRole(ctx, &pb.CreateRoleRequest{Name: "platform_admin"})
	_, _ = srv.AddPermission(ctx, &pb.AddPermissionRequest{
		Role: "platform_admin", Resource: "**", Action: "*",
	})

	_, _ = srv.AssignRole(ctx, &pb.AssignRoleRequest{
		Subject:   "admin-1",
		Role:      "platform_admin",
		ScopeType: "platform",
	})

	resp, err := srv.CheckAccess(ctx, &pb.CheckAccessRequest{
		Subject:   "admin-1",
		Resource:  "prices",
		Action:    "generate",
		ScopeType: "tenant",
		ScopeId:   "any-tenant",
	})
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if !resp.Allowed {
		t.Error("expected platform admin allowed in any tenant scope")
	}
}

func TestAssignAndListRoles_Scoped(t *testing.T) {
	srv, ctx := setupTestServer(t)

	_, _ = srv.CreateRole(ctx, &pb.CreateRoleRequest{Name: "tenant_owner"})
	_, _ = srv.CreateRole(ctx, &pb.CreateRoleRequest{Name: "tenant_viewer"})

	_, _ = srv.AssignRole(ctx, &pb.AssignRoleRequest{
		Subject: "u1", Role: "tenant_owner", ScopeType: "tenant", ScopeId: "t-a",
	})
	_, _ = srv.AssignRole(ctx, &pb.AssignRoleRequest{
		Subject: "u1", Role: "tenant_viewer", ScopeType: "tenant", ScopeId: "t-b",
	})

	resp, _ := srv.ListSubjectRoles(ctx, &pb.ListSubjectRolesRequest{
		Subject: "u1", ScopeType: "tenant", ScopeId: "t-a",
	})
	if len(resp.Roles) != 1 || resp.Roles[0] != "tenant_owner" {
		t.Errorf("tenant-a: expected [tenant_owner], got %v", resp.Roles)
	}

	resp, _ = srv.ListSubjectRoles(ctx, &pb.ListSubjectRolesRequest{
		Subject: "u1", ScopeType: "tenant", ScopeId: "t-b",
	})
	if len(resp.Roles) != 1 || resp.Roles[0] != "tenant_viewer" {
		t.Errorf("tenant-b: expected [tenant_viewer], got %v", resp.Roles)
	}
}

func TestRevokeRole_Scoped(t *testing.T) {
	srv, ctx := setupTestServer(t)

	_, _ = srv.CreateRole(ctx, &pb.CreateRoleRequest{Name: "member"})
	_, _ = srv.AssignRole(ctx, &pb.AssignRoleRequest{
		Subject: "u1", Role: "member", ScopeType: "tenant", ScopeId: "t1",
	})
	_, _ = srv.AssignRole(ctx, &pb.AssignRoleRequest{
		Subject: "u1", Role: "member", ScopeType: "tenant", ScopeId: "t2",
	})

	_, err := srv.RevokeRole(ctx, &pb.RevokeRoleRequest{
		Subject: "u1", Role: "member", ScopeType: "tenant", ScopeId: "t1",
	})
	if err != nil {
		t.Fatalf("RevokeRole: %v", err)
	}

	resp, _ := srv.ListSubjectRoles(ctx, &pb.ListSubjectRolesRequest{
		Subject: "u1", ScopeType: "tenant", ScopeId: "t1",
	})
	if len(resp.Roles) != 0 {
		t.Errorf("expected empty after revoke, got %v", resp.Roles)
	}

	resp, _ = srv.ListSubjectRoles(ctx, &pb.ListSubjectRolesRequest{
		Subject: "u1", ScopeType: "tenant", ScopeId: "t2",
	})
	if len(resp.Roles) != 1 {
		t.Errorf("expected [member] in t2, got %v", resp.Roles)
	}
}

func TestValidateScope(t *testing.T) {
	tests := []struct {
		name      string
		scopeType string
		scopeID   string
		wantErr   bool
	}{
		{"empty scope_type", "", "", true},
		{"invalid scope_type", "org", "", true},
		{"platform valid", "platform", "", false},
		{"platform with scope_id", "platform", "x", false},
		{"tenant without scope_id", "tenant", "", true},
		{"tenant valid", "tenant", "t-123", false},
	}

	for _, tt := range tests {
		err := validateScope(tt.scopeType, tt.scopeID)
		if (err != nil) != tt.wantErr {
			t.Errorf("%s: err=%v, wantErr=%v", tt.name, err, tt.wantErr)
		}
		if err != nil && status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: expected InvalidArgument, got %v", tt.name, status.Code(err))
		}
	}
}
