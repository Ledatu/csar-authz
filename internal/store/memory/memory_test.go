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
	_ = s.AssignRole(ctx, "user-1", "admin", "platform", "")
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
	roles, _ := s.GetSubjectRoles(ctx, "user-1", "platform", "")
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

	_ = s.AssignRole(ctx, "user-1", "admin", "platform", "")
	_ = s.AssignRole(ctx, "user-1", "viewer", "platform", "")

	roles, err := s.GetSubjectRoles(ctx, "user-1", "platform", "")
	if err != nil {
		t.Fatalf("GetSubjectRoles: %v", err)
	}
	if len(roles) != 2 {
		t.Errorf("expected 2 roles, got %d: %v", len(roles), roles)
	}
}

func TestAssignRoleNotFound(t *testing.T) {
	s := New()
	err := s.AssignRole(context.Background(), "user-1", "nonexistent", "platform", "")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestRevokeRole(t *testing.T) {
	s := New()
	ctx := context.Background()

	_ = s.CreateRole(ctx, &store.Role{Name: "admin"})
	_ = s.AssignRole(ctx, "user-1", "admin", "platform", "")
	_ = s.RevokeRole(ctx, "user-1", "admin", "platform", "")

	roles, _ := s.GetSubjectRoles(ctx, "user-1", "platform", "")
	if len(roles) != 0 {
		t.Errorf("expected no roles after revoke, got %v", roles)
	}
}

func TestGetSubjectRolesEmpty(t *testing.T) {
	s := New()
	roles, err := s.GetSubjectRoles(context.Background(), "unknown", "platform", "")
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
	assignments := []store.ScopedAssignment{
		{Subject: "alice", Role: "admin", ScopeType: "platform", ScopeID: ""},
		{Subject: "bob", Role: "viewer", ScopeType: "platform", ScopeID: ""},
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
	aliceRoles, _ := s.GetSubjectRoles(ctx, "alice", "platform", "")
	if len(aliceRoles) != 1 || aliceRoles[0] != "admin" {
		t.Fatalf("alice roles = %v, want [admin]", aliceRoles)
	}
}

func TestSync_ReplacesExisting(t *testing.T) {
	s := New()
	ctx := context.Background()

	// Initial state.
	_ = s.CreateRole(ctx, &store.Role{Name: "old"})
	_ = s.AssignRole(ctx, "user", "old", "platform", "")

	// Sync replaces everything.
	roles := []*store.Role{{Name: "new"}}
	perms := []*store.Permission{{Role: "new", Resource: "/**", Action: "*"}}
	assignments := []store.ScopedAssignment{
		{Subject: "user", Role: "new", ScopeType: "platform", ScopeID: ""},
	}

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
	assignments := []store.ScopedAssignment{
		{Subject: "user", Role: "nonexistent", ScopeType: "platform", ScopeID: ""},
	}

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

// --- Tenant-scoped assignment tests ---

func TestScopedAssignments_Isolation(t *testing.T) {
	s := New()
	ctx := context.Background()

	_ = s.CreateRole(ctx, &store.Role{Name: "owner"})
	_ = s.CreateRole(ctx, &store.Role{Name: "viewer"})

	_ = s.AssignRole(ctx, "user-42", "owner", "tenant", "t-a")
	_ = s.AssignRole(ctx, "user-42", "viewer", "tenant", "t-b")

	rolesA, _ := s.GetSubjectRoles(ctx, "user-42", "tenant", "t-a")
	if len(rolesA) != 1 || rolesA[0] != "owner" {
		t.Errorf("tenant-a: expected [owner], got %v", rolesA)
	}

	rolesB, _ := s.GetSubjectRoles(ctx, "user-42", "tenant", "t-b")
	if len(rolesB) != 1 || rolesB[0] != "viewer" {
		t.Errorf("tenant-b: expected [viewer], got %v", rolesB)
	}

	// Platform scope should be empty for this user.
	rolesPlatform, _ := s.GetSubjectRoles(ctx, "user-42", "platform", "")
	if len(rolesPlatform) != 0 {
		t.Errorf("platform: expected empty, got %v", rolesPlatform)
	}
}

func TestScopedAssignments_RevokeScope(t *testing.T) {
	s := New()
	ctx := context.Background()

	_ = s.CreateRole(ctx, &store.Role{Name: "admin"})
	_ = s.AssignRole(ctx, "user-1", "admin", "tenant", "t1")
	_ = s.AssignRole(ctx, "user-1", "admin", "tenant", "t2")

	// Revoke from t1 only.
	_ = s.RevokeRole(ctx, "user-1", "admin", "tenant", "t1")

	roles1, _ := s.GetSubjectRoles(ctx, "user-1", "tenant", "t1")
	if len(roles1) != 0 {
		t.Errorf("expected empty after revoke from t1, got %v", roles1)
	}

	// t2 should be unaffected.
	roles2, _ := s.GetSubjectRoles(ctx, "user-1", "tenant", "t2")
	if len(roles2) != 1 {
		t.Errorf("expected [admin] in t2, got %v", roles2)
	}
}

func TestSync_ScopedAssignments(t *testing.T) {
	s := New()
	ctx := context.Background()

	roles := []*store.Role{
		{Name: "platform_admin"},
		{Name: "tenant_viewer"},
	}
	assignments := []store.ScopedAssignment{
		{Subject: "admin-1", Role: "platform_admin", ScopeType: "platform", ScopeID: ""},
		{Subject: "user-42", Role: "tenant_viewer", ScopeType: "tenant", ScopeID: "t-100"},
	}

	if err := s.Sync(ctx, roles, nil, assignments); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	adminRoles, _ := s.GetSubjectRoles(ctx, "admin-1", "platform", "")
	if len(adminRoles) != 1 || adminRoles[0] != "platform_admin" {
		t.Errorf("expected [platform_admin], got %v", adminRoles)
	}

	userRoles, _ := s.GetSubjectRoles(ctx, "user-42", "tenant", "t-100")
	if len(userRoles) != 1 || userRoles[0] != "tenant_viewer" {
		t.Errorf("expected [tenant_viewer], got %v", userRoles)
	}

	// User should not appear in platform scope.
	userPlatform, _ := s.GetSubjectRoles(ctx, "user-42", "platform", "")
	if len(userPlatform) != 0 {
		t.Errorf("expected empty platform roles for user-42, got %v", userPlatform)
	}
}
