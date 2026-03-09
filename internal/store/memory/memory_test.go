package memory

import (
	"context"
	"errors"
	"testing"

	"github.com/ledatu/csar-authz/internal/store"
)

func TestCreateAndGetRole(t *testing.T) {
	s := New()
	ctx := context.Background()

	err := s.CreateRole(ctx, &store.Role{Name: "admin", Description: "Administrator"})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}

	r, err := s.GetRole(ctx, "admin")
	if err != nil {
		t.Fatalf("GetRole: %v", err)
	}
	if r.Name != "admin" || r.Description != "Administrator" {
		t.Errorf("got %+v", r)
	}
}

func TestCreateRoleDuplicate(t *testing.T) {
	s := New()
	ctx := context.Background()

	_ = s.CreateRole(ctx, &store.Role{Name: "admin"})
	err := s.CreateRole(ctx, &store.Role{Name: "admin"})
	if !errors.Is(err, store.ErrAlreadyExists) {
		t.Errorf("expected ErrAlreadyExists, got %v", err)
	}
}

func TestCreateRoleWithInvalidParent(t *testing.T) {
	s := New()
	ctx := context.Background()

	err := s.CreateRole(ctx, &store.Role{Name: "editor", Parents: []string{"nonexistent"}})
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound for parent, got %v", err)
	}
}

func TestCreateRoleWithParent(t *testing.T) {
	s := New()
	ctx := context.Background()

	_ = s.CreateRole(ctx, &store.Role{Name: "viewer"})
	err := s.CreateRole(ctx, &store.Role{Name: "editor", Parents: []string{"viewer"}})
	if err != nil {
		t.Fatalf("CreateRole with parent: %v", err)
	}

	r, _ := s.GetRole(ctx, "editor")
	if len(r.Parents) != 1 || r.Parents[0] != "viewer" {
		t.Errorf("expected parents=[viewer], got %v", r.Parents)
	}
}

func TestDeleteRole(t *testing.T) {
	s := New()
	ctx := context.Background()

	_ = s.CreateRole(ctx, &store.Role{Name: "admin"})
	_ = s.AssignRole(ctx, "user-1", "admin")
	_ = s.AddPermission(ctx, &store.Permission{Role: "admin", Resource: "/**", Action: "*"})

	err := s.DeleteRole(ctx, "admin")
	if err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}

	_, err = s.GetRole(ctx, "admin")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}

	// Assignments should be cleaned up.
	roles, _ := s.GetSubjectRoles(ctx, "user-1")
	if len(roles) != 0 {
		t.Errorf("expected no roles after delete, got %v", roles)
	}

	// Permissions should be cleaned up.
	perms, _ := s.GetRolePermissions(ctx, "admin")
	if len(perms) != 0 {
		t.Errorf("expected no permissions after delete, got %v", perms)
	}
}

func TestDeleteRoleNotFound(t *testing.T) {
	s := New()
	err := s.DeleteRole(context.Background(), "nope")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestListRoles(t *testing.T) {
	s := New()
	ctx := context.Background()

	_ = s.CreateRole(ctx, &store.Role{Name: "admin"})
	_ = s.CreateRole(ctx, &store.Role{Name: "viewer"})

	roles, err := s.ListRoles(ctx)
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if len(roles) != 2 {
		t.Errorf("expected 2 roles, got %d", len(roles))
	}
}

func TestAssignAndGetSubjectRoles(t *testing.T) {
	s := New()
	ctx := context.Background()

	_ = s.CreateRole(ctx, &store.Role{Name: "admin"})
	_ = s.CreateRole(ctx, &store.Role{Name: "viewer"})

	_ = s.AssignRole(ctx, "user-1", "admin")
	_ = s.AssignRole(ctx, "user-1", "viewer")

	roles, err := s.GetSubjectRoles(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetSubjectRoles: %v", err)
	}
	if len(roles) != 2 {
		t.Errorf("expected 2 roles, got %d: %v", len(roles), roles)
	}
}

func TestAssignRoleNotFound(t *testing.T) {
	s := New()
	err := s.AssignRole(context.Background(), "user-1", "nonexistent")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestRevokeRole(t *testing.T) {
	s := New()
	ctx := context.Background()

	_ = s.CreateRole(ctx, &store.Role{Name: "admin"})
	_ = s.AssignRole(ctx, "user-1", "admin")
	_ = s.RevokeRole(ctx, "user-1", "admin")

	roles, _ := s.GetSubjectRoles(ctx, "user-1")
	if len(roles) != 0 {
		t.Errorf("expected no roles after revoke, got %v", roles)
	}
}

func TestGetSubjectRolesEmpty(t *testing.T) {
	s := New()
	roles, err := s.GetSubjectRoles(context.Background(), "unknown")
	if err != nil {
		t.Fatalf("GetSubjectRoles: %v", err)
	}
	if len(roles) != 0 {
		t.Errorf("expected empty, got %v", roles)
	}
}

func TestAddAndGetPermissions(t *testing.T) {
	s := New()
	ctx := context.Background()

	_ = s.CreateRole(ctx, &store.Role{Name: "editor"})

	err := s.AddPermission(ctx, &store.Permission{
		Role:     "editor",
		Resource: "/api/v1/posts/*",
		Action:   "PUT",
	})
	if err != nil {
		t.Fatalf("AddPermission: %v", err)
	}

	perms, err := s.GetRolePermissions(ctx, "editor")
	if err != nil {
		t.Fatalf("GetRolePermissions: %v", err)
	}
	if len(perms) != 1 {
		t.Fatalf("expected 1 permission, got %d", len(perms))
	}
	if perms[0].Resource != "/api/v1/posts/*" || perms[0].Action != "PUT" {
		t.Errorf("unexpected permission: %+v", perms[0])
	}
	if perms[0].ID == "" {
		t.Error("permission ID should be auto-generated")
	}
}

func TestAddPermissionRoleNotFound(t *testing.T) {
	s := New()
	err := s.AddPermission(context.Background(), &store.Permission{
		Role:     "nonexistent",
		Resource: "/",
		Action:   "GET",
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestRemovePermission(t *testing.T) {
	s := New()
	ctx := context.Background()

	_ = s.CreateRole(ctx, &store.Role{Name: "editor"})
	_ = s.AddPermission(ctx, &store.Permission{Role: "editor", Resource: "/a", Action: "GET"})
	_ = s.AddPermission(ctx, &store.Permission{Role: "editor", Resource: "/b", Action: "POST"})

	perms, _ := s.GetRolePermissions(ctx, "editor")
	if len(perms) != 2 {
		t.Fatalf("expected 2 permissions, got %d", len(perms))
	}

	err := s.RemovePermission(ctx, perms[0].ID)
	if err != nil {
		t.Fatalf("RemovePermission: %v", err)
	}

	perms, _ = s.GetRolePermissions(ctx, "editor")
	if len(perms) != 1 {
		t.Errorf("expected 1 permission after removal, got %d", len(perms))
	}
}

func TestRemovePermissionNotFound(t *testing.T) {
	s := New()
	err := s.RemovePermission(context.Background(), "nonexistent")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestSync_Basic(t *testing.T) {
	s := New()
	ctx := context.Background()

	roles := []*store.Role{
		{Name: "viewer", Description: "Read-only"},
		{Name: "admin", Description: "Full access", Parents: []string{"viewer"}},
	}
	perms := []*store.Permission{
		{Role: "viewer", Resource: "/api/**", Action: "GET"},
		{Role: "admin", Resource: "/**", Action: "*"},
	}
	assignments := map[string][]string{
		"alice": {"admin"},
		"bob":   {"viewer"},
	}

	if err := s.Sync(ctx, roles, perms, assignments); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	// Verify roles.
	allRoles, _ := s.ListRoles(ctx)
	if len(allRoles) != 2 {
		t.Fatalf("roles = %d, want 2", len(allRoles))
	}

	// Verify permissions.
	viewerPerms, _ := s.GetRolePermissions(ctx, "viewer")
	if len(viewerPerms) != 1 {
		t.Fatalf("viewer perms = %d, want 1", len(viewerPerms))
	}

	// Verify assignments.
	aliceRoles, _ := s.GetSubjectRoles(ctx, "alice")
	if len(aliceRoles) != 1 || aliceRoles[0] != "admin" {
		t.Fatalf("alice roles = %v, want [admin]", aliceRoles)
	}
}

func TestSync_ReplacesExisting(t *testing.T) {
	s := New()
	ctx := context.Background()

	// Initial state.
	_ = s.CreateRole(ctx, &store.Role{Name: "old"})
	_ = s.AssignRole(ctx, "user", "old")

	// Sync replaces everything.
	roles := []*store.Role{{Name: "new"}}
	perms := []*store.Permission{{Role: "new", Resource: "/**", Action: "*"}}
	assignments := map[string][]string{"user": {"new"}}

	if err := s.Sync(ctx, roles, perms, assignments); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	// Old role should be gone.
	_, err := s.GetRole(ctx, "old")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatal("old role should not exist after sync")
	}

	// New role should exist.
	r, err := s.GetRole(ctx, "new")
	if err != nil {
		t.Fatal(err)
	}
	if r.Name != "new" {
		t.Fatalf("role name = %q, want new", r.Name)
	}
}

func TestSync_InvalidParent(t *testing.T) {
	s := New()
	ctx := context.Background()

	roles := []*store.Role{
		{Name: "child", Parents: []string{"nonexistent"}},
	}

	err := s.Sync(ctx, roles, nil, nil)
	if err == nil {
		t.Fatal("expected error for invalid parent")
	}
}

func TestSync_InvalidPermissionRole(t *testing.T) {
	s := New()
	ctx := context.Background()

	roles := []*store.Role{{Name: "admin"}}
	perms := []*store.Permission{{Role: "nonexistent", Resource: "/**", Action: "*"}}

	err := s.Sync(ctx, roles, perms, nil)
	if err == nil {
		t.Fatal("expected error for invalid permission role")
	}
}

func TestSync_InvalidAssignmentRole(t *testing.T) {
	s := New()
	ctx := context.Background()

	roles := []*store.Role{{Name: "admin"}}
	assignments := map[string][]string{"user": {"nonexistent"}}

	err := s.Sync(ctx, roles, nil, assignments)
	if err == nil {
		t.Fatal("expected error for invalid assignment role")
	}
}

func TestDeleteRoleCleansParentReferences(t *testing.T) {
	s := New()
	ctx := context.Background()

	_ = s.CreateRole(ctx, &store.Role{Name: "viewer"})
	_ = s.CreateRole(ctx, &store.Role{Name: "editor", Parents: []string{"viewer"}})

	_ = s.DeleteRole(ctx, "viewer")

	r, _ := s.GetRole(ctx, "editor")
	if len(r.Parents) != 0 {
		t.Errorf("expected parent reference cleaned, got %v", r.Parents)
	}
}
