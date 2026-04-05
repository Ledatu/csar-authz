package postgres

import (
	"context"
	"os"
	"reflect"
	"testing"

	"github.com/ledatu/csar-authz/internal/store"
)

// testStore creates a postgres-backed store for testing.
// Skips the test if CSAR_TEST_DSN is not set.
func testStore(t *testing.T) *Store {
	t.Helper()

	dsn := os.Getenv("CSAR_TEST_DSN")
	if dsn == "" {
		t.Skip("CSAR_TEST_DSN not set; skipping postgres test")
	}

	ctx := context.Background()
	s, err := New(ctx, dsn)
	if err != nil {
		t.Fatalf("creating postgres store: %v", err)
	}
	t.Cleanup(s.Close)

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("running migrations: %v", err)
	}

	// Clear all tables before each test to ensure isolation.
	for _, table := range []string{"assignments", "permissions", "role_parents", "roles"} {
		if _, err := s.pool.Exec(ctx, "DELETE FROM "+table); err != nil {
			t.Fatalf("clearing %s: %v", table, err)
		}
	}

	return s
}

func TestSyncPolicy_PreservesAssignments_PG(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	roles := []*store.Role{
		{Name: "viewer", Description: "Read-only"},
		{Name: "admin", Description: "Full access", Parents: []string{"viewer"}},
	}
	perms := []*store.Permission{
		{Role: "admin", Resource: "/**", Action: "*"},
	}

	if err := s.SyncPolicy(ctx, roles, perms); err != nil {
		t.Fatalf("initial SyncPolicy: %v", err)
	}

	if err := s.AssignRole(ctx, "alice", "admin", "platform", ""); err != nil {
		t.Fatalf("AssignRole alice: %v", err)
	}
	if err := s.AssignRole(ctx, "bob", "viewer", "tenant", "t-1"); err != nil {
		t.Fatalf("AssignRole bob: %v", err)
	}

	// Re-sync with updated permissions but same roles.
	perms = []*store.Permission{
		{Role: "admin", Resource: "/**", Action: "*"},
		{Role: "viewer", Resource: "/api/**", Action: "GET"},
	}
	if err := s.SyncPolicy(ctx, roles, perms); err != nil {
		t.Fatalf("second SyncPolicy: %v", err)
	}

	aliceRoles, err := s.GetSubjectRoles(ctx, "alice", "platform", "")
	if err != nil {
		t.Fatalf("GetSubjectRoles alice: %v", err)
	}
	if len(aliceRoles) != 1 || aliceRoles[0] != "admin" {
		t.Fatalf("alice roles = %v, want [admin]", aliceRoles)
	}

	bobRoles, err := s.GetSubjectRoles(ctx, "bob", "tenant", "t-1")
	if err != nil {
		t.Fatalf("GetSubjectRoles bob: %v", err)
	}
	if len(bobRoles) != 1 || bobRoles[0] != "viewer" {
		t.Fatalf("bob roles = %v, want [viewer]", bobRoles)
	}
}

func TestSyncPolicy_PrunesObsoleteRole_PG(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	roles := []*store.Role{{Name: "admin"}, {Name: "viewer"}}
	if err := s.SyncPolicy(ctx, roles, nil); err != nil {
		t.Fatalf("SyncPolicy: %v", err)
	}

	_ = s.AssignRole(ctx, "alice", "admin", "platform", "")
	_ = s.AssignRole(ctx, "alice", "viewer", "platform", "")

	// Re-sync without "admin" — cascade should remove alice's admin assignment.
	if err := s.SyncPolicy(ctx, []*store.Role{{Name: "viewer"}}, nil); err != nil {
		t.Fatalf("SyncPolicy: %v", err)
	}

	aliceRoles, _ := s.GetSubjectRoles(ctx, "alice", "platform", "")
	if len(aliceRoles) != 1 || aliceRoles[0] != "viewer" {
		t.Fatalf("alice roles = %v, want [viewer]", aliceRoles)
	}

	_, err := s.GetRole(ctx, "admin")
	if err != store.ErrNotFound {
		t.Fatalf("expected ErrNotFound for pruned role, got %v", err)
	}
}

func TestSyncPolicy_UpsertUpdatesDescription_PG(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	roles := []*store.Role{{Name: "admin", Description: "old"}}
	if err := s.SyncPolicy(ctx, roles, nil); err != nil {
		t.Fatalf("SyncPolicy: %v", err)
	}

	_ = s.AssignRole(ctx, "alice", "admin", "platform", "")

	roles = []*store.Role{{Name: "admin", Description: "new"}}
	if err := s.SyncPolicy(ctx, roles, nil); err != nil {
		t.Fatalf("SyncPolicy: %v", err)
	}

	r, err := s.GetRole(ctx, "admin")
	if err != nil {
		t.Fatalf("GetRole: %v", err)
	}
	if r.Description != "new" {
		t.Fatalf("description = %q, want new", r.Description)
	}

	aliceRoles, _ := s.GetSubjectRoles(ctx, "alice", "platform", "")
	if len(aliceRoles) != 1 || aliceRoles[0] != "admin" {
		t.Fatalf("alice roles = %v, want [admin]", aliceRoles)
	}
}

func TestSyncPolicy_EmptyRoleList_PG(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	roles := []*store.Role{{Name: "admin"}}
	if err := s.SyncPolicy(ctx, roles, nil); err != nil {
		t.Fatalf("SyncPolicy: %v", err)
	}
	_ = s.AssignRole(ctx, "alice", "admin", "platform", "")

	// Sync with empty roles — everything should be pruned.
	if err := s.SyncPolicy(ctx, nil, nil); err != nil {
		t.Fatalf("SyncPolicy empty: %v", err)
	}

	allRoles, _ := s.ListRoles(ctx)
	if len(allRoles) != 0 {
		t.Fatalf("roles = %d, want 0", len(allRoles))
	}

	aliceRoles, _ := s.GetSubjectRoles(ctx, "alice", "platform", "")
	if len(aliceRoles) != 0 {
		t.Fatalf("alice roles = %v, want []", aliceRoles)
	}
}

func TestListSubjectAssignments_PG(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	if err := s.SyncPolicy(ctx, []*store.Role{
		{Name: "platform_admin"},
		{Name: "tenant_admin"},
	}, nil); err != nil {
		t.Fatalf("SyncPolicy: %v", err)
	}
	_ = s.AssignRole(ctx, "alice", "platform_admin", "platform", "")
	_ = s.AssignRole(ctx, "alice", "tenant_admin", "tenant", "acme")

	assignments, err := s.ListSubjectAssignments(ctx, "alice")
	if err != nil {
		t.Fatalf("ListSubjectAssignments: %v", err)
	}
	if len(assignments) != 2 {
		t.Fatalf("expected 2 assignments, got %d", len(assignments))
	}
	if assignments[0].ScopeType != "platform" || assignments[0].Role != "platform_admin" {
		t.Fatalf("unexpected first assignment: %+v", assignments[0])
	}
	if assignments[1].ScopeType != "tenant" || assignments[1].ScopeID != "acme" || assignments[1].Role != "tenant_admin" {
		t.Fatalf("unexpected second assignment: %+v", assignments[1])
	}
}

func TestListRoleClosure_PG(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	if err := s.SyncPolicy(ctx, []*store.Role{
		{Name: "base"},
		{Name: "level1", Parents: []string{"base"}},
		{Name: "level2", Parents: []string{"level1"}},
		{Name: "level3", Parents: []string{"level2"}},
	}, nil); err != nil {
		t.Fatalf("SyncPolicy: %v", err)
	}

	closure, err := s.ListRoleClosure(ctx, []string{"level3"})
	if err != nil {
		t.Fatalf("ListRoleClosure: %v", err)
	}
	want := []string{"level3", "level2", "level1", "base"}
	if !reflect.DeepEqual(closure["level3"], want) {
		t.Fatalf("level3 closure = %v, want %v", closure["level3"], want)
	}
}

func TestListRoleClosure_MultiSeedMissingAndDedupe_PG(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	if err := s.SyncPolicy(ctx, []*store.Role{
		{Name: "viewer"},
		{Name: "editor", Parents: []string{"viewer"}},
		{Name: "admin", Parents: []string{"viewer"}},
	}, nil); err != nil {
		t.Fatalf("SyncPolicy: %v", err)
	}

	closure, err := s.ListRoleClosure(ctx, []string{"editor", "missing", "admin", "editor"})
	if err != nil {
		t.Fatalf("ListRoleClosure: %v", err)
	}
	if !reflect.DeepEqual(closure["editor"], []string{"editor", "viewer"}) {
		t.Fatalf("editor closure = %v", closure["editor"])
	}
	if !reflect.DeepEqual(closure["admin"], []string{"admin", "viewer"}) {
		t.Fatalf("admin closure = %v", closure["admin"])
	}
	if got := closure["missing"]; len(got) != 0 {
		t.Fatalf("missing closure = %v, want empty", got)
	}
	if len(closure) != 3 {
		t.Fatalf("expected closures for 3 unique seeds, got %d", len(closure))
	}
}

func TestListRoleClosure_Cycle_PG(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	if err := s.SyncPolicy(ctx, []*store.Role{
		{Name: "role_a", Parents: []string{"role_b"}},
		{Name: "role_b", Parents: []string{"role_a"}},
	}, nil); err != nil {
		t.Fatalf("SyncPolicy: %v", err)
	}

	closure, err := s.ListRoleClosure(ctx, []string{"role_a"})
	if err != nil {
		t.Fatalf("ListRoleClosure: %v", err)
	}
	want := []string{"role_a", "role_b"}
	if !reflect.DeepEqual(closure["role_a"], want) {
		t.Fatalf("role_a closure = %v, want %v", closure["role_a"], want)
	}
}

func TestListPermissionsForRoles_PG(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	if err := s.SyncPolicy(ctx, []*store.Role{
		{Name: "editor"},
		{Name: "viewer"},
	}, []*store.Permission{
		{Role: "editor", Resource: "/edit", Action: "POST"},
		{Role: "viewer", Resource: "/view", Action: "GET"},
	}); err != nil {
		t.Fatalf("SyncPolicy: %v", err)
	}

	perms, err := s.ListPermissionsForRoles(ctx, []string{"viewer", "editor", "viewer"})
	if err != nil {
		t.Fatalf("ListPermissionsForRoles: %v", err)
	}
	if len(perms["editor"]) != 1 || perms["editor"][0].Action != "POST" {
		t.Fatalf("unexpected editor permissions: %+v", perms["editor"])
	}
	if len(perms["viewer"]) != 1 || perms["viewer"][0].Action != "GET" {
		t.Fatalf("unexpected viewer permissions: %+v", perms["viewer"])
	}
}
