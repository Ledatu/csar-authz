package server

import (
	"context"
	"testing"

	"github.com/ledatu/csar-authz/internal/engine"
	"github.com/ledatu/csar-authz/internal/store/memory"
	pb "github.com/ledatu/csar-authz/proto/authz/v1"
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
		{"empty subject", &pb.CheckAccessRequest{Resource: "/api", Action: "GET"}},
		{"empty resource", &pb.CheckAccessRequest{Subject: "u1", Action: "GET"}},
		{"empty action", &pb.CheckAccessRequest{Subject: "u1", Resource: "/api"}},
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

	// Create role and permission.
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

	// Assign role.
	_, err = srv.AssignRole(ctx, &pb.AssignRoleRequest{
		Subject: "user-1",
		Role:    "viewer",
	})
	if err != nil {
		t.Fatalf("AssignRole: %v", err)
	}

	// CheckAccess: allowed.
	resp, err := srv.CheckAccess(ctx, &pb.CheckAccessRequest{
		Subject:  "user-1",
		Resource: "/api/v1/projects",
		Action:   "GET",
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

	// CheckAccess: denied (wrong action).
	resp, err = srv.CheckAccess(ctx, &pb.CheckAccessRequest{
		Subject:  "user-1",
		Resource: "/api/v1/projects",
		Action:   "DELETE",
	})
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if resp.Allowed {
		t.Error("expected denied for DELETE")
	}

	// CheckAccess: denied (unknown user).
	resp, err = srv.CheckAccess(ctx, &pb.CheckAccessRequest{
		Subject:  "unknown-user",
		Resource: "/api/v1/projects",
		Action:   "GET",
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
		Subject: "user-1",
		Role:    "nonexistent",
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("expected NotFound, got %v", err)
	}
}

func TestListSubjectRoles(t *testing.T) {
	srv, ctx := setupTestServer(t)

	_, _ = srv.CreateRole(ctx, &pb.CreateRoleRequest{Name: "admin"})
	_, _ = srv.CreateRole(ctx, &pb.CreateRoleRequest{Name: "viewer"})
	_, _ = srv.AssignRole(ctx, &pb.AssignRoleRequest{Subject: "u1", Role: "admin"})
	_, _ = srv.AssignRole(ctx, &pb.AssignRoleRequest{Subject: "u1", Role: "viewer"})

	resp, err := srv.ListSubjectRoles(ctx, &pb.ListSubjectRolesRequest{Subject: "u1"})
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
	_, _ = srv.AssignRole(ctx, &pb.AssignRoleRequest{Subject: "u1", Role: "admin"})
	_, err := srv.RevokeRole(ctx, &pb.RevokeRoleRequest{Subject: "u1", Role: "admin"})
	if err != nil {
		t.Fatalf("RevokeRole: %v", err)
	}

	resp, _ := srv.ListSubjectRoles(ctx, &pb.ListSubjectRolesRequest{Subject: "u1"})
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

	// base role with read permission
	_, _ = srv.CreateRole(ctx, &pb.CreateRoleRequest{Name: "reader"})
	_, _ = srv.AddPermission(ctx, &pb.AddPermissionRequest{
		Role: "reader", Resource: "/api/**", Action: "GET",
	})

	// editor inherits reader, adds write
	_, _ = srv.CreateRole(ctx, &pb.CreateRoleRequest{
		Name: "editor", Parents: []string{"reader"},
	})
	_, _ = srv.AddPermission(ctx, &pb.AddPermissionRequest{
		Role: "editor", Resource: "/api/v1/posts/**", Action: "PUT",
	})

	_, _ = srv.AssignRole(ctx, &pb.AssignRoleRequest{Subject: "u1", Role: "editor"})

	// GET via inherited reader
	resp, _ := srv.CheckAccess(ctx, &pb.CheckAccessRequest{
		Subject: "u1", Resource: "/api/v1/users", Action: "GET",
	})
	if !resp.Allowed {
		t.Error("expected GET allowed via inherited reader")
	}

	// PUT on posts via direct editor
	resp, _ = srv.CheckAccess(ctx, &pb.CheckAccessRequest{
		Subject: "u1", Resource: "/api/v1/posts/123", Action: "PUT",
	})
	if !resp.Allowed {
		t.Error("expected PUT allowed via editor")
	}

	// DELETE denied
	resp, _ = srv.CheckAccess(ctx, &pb.CheckAccessRequest{
		Subject: "u1", Resource: "/api/v1/posts/123", Action: "DELETE",
	})
	if resp.Allowed {
		t.Error("expected DELETE denied")
	}
}
