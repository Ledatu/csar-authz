package engine

import (
	"context"
	"testing"

	"github.com/ledatu/csar-authz/internal/store"
	"github.com/ledatu/csar-authz/internal/store/memory"
)

// setupTestEngine creates an engine with a memory store and common test data.
func setupTestEngine(t *testing.T) (*Engine, context.Context) {
	t.Helper()
	s := memory.New()
	e := New(s)
	ctx := context.Background()
	return e, ctx
}

func TestCheckAccess_NoRoles(t *testing.T) {
	e, ctx := setupTestEngine(t)

	result, err := e.CheckAccess(ctx, "user-1", "platform", "", "/api/v1/users", "GET")
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if result.Allowed {
		t.Error("expected denied for user with no roles")
	}
}

func TestCheckAccess_DirectRole(t *testing.T) {
	e, ctx := setupTestEngine(t)

	_ = e.CreateRole(ctx, &store.Role{Name: "viewer"})
	_ = e.AddPermission(ctx, &store.Permission{Role: "viewer", Resource: "/api/v1/**", Action: "GET"})
	_ = e.AssignRole(ctx, "user-1", "viewer", "platform", "")

	// Allowed: GET on matching path.
	result, err := e.CheckAccess(ctx, "user-1", "platform", "", "/api/v1/users", "GET")
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if !result.Allowed {
		t.Error("expected allowed")
	}
	if len(result.MatchedRoles) != 1 || result.MatchedRoles[0] != "viewer" {
		t.Errorf("expected matched_roles=[viewer], got %v", result.MatchedRoles)
	}

	// Denied: POST on matching path (wrong action).
	result, err = e.CheckAccess(ctx, "user-1", "platform", "", "/api/v1/users", "POST")
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if result.Allowed {
		t.Error("expected denied for POST")
	}
}

func TestCheckAccess_WildcardAction(t *testing.T) {
	e, ctx := setupTestEngine(t)

	_ = e.CreateRole(ctx, &store.Role{Name: "admin"})
	_ = e.AddPermission(ctx, &store.Permission{Role: "admin", Resource: "/**", Action: "*"})
	_ = e.AssignRole(ctx, "admin-user", "admin", "platform", "")

	for _, method := range []string{"GET", "POST", "PUT", "DELETE", "PATCH"} {
		result, err := e.CheckAccess(ctx, "admin-user", "platform", "", "/api/v1/anything/here", method)
		if err != nil {
			t.Fatalf("CheckAccess %s: %v", method, err)
		}
		if !result.Allowed {
			t.Errorf("expected allowed for %s", method)
		}
	}
}

func TestCheckAccess_RoleHierarchy(t *testing.T) {
	e, ctx := setupTestEngine(t)

	// viewer can read.
	_ = e.CreateRole(ctx, &store.Role{Name: "viewer"})
	_ = e.AddPermission(ctx, &store.Permission{Role: "viewer", Resource: "/api/**", Action: "GET"})

	// editor inherits from viewer and can also write.
	_ = e.CreateRole(ctx, &store.Role{Name: "editor", Parents: []string{"viewer"}})
	_ = e.AddPermission(ctx, &store.Permission{Role: "editor", Resource: "/api/v1/posts/*", Action: "PUT"})

	_ = e.AssignRole(ctx, "user-1", "editor", "platform", "")

	// Should be allowed to GET (inherited from viewer).
	result, err := e.CheckAccess(ctx, "user-1", "platform", "", "/api/v1/users", "GET")
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if !result.Allowed {
		t.Error("expected allowed via inherited viewer role")
	}

	// Should be allowed to PUT posts (direct editor permission).
	result, err = e.CheckAccess(ctx, "user-1", "platform", "", "/api/v1/posts/123", "PUT")
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if !result.Allowed {
		t.Error("expected allowed via direct editor permission")
	}

	// Should be denied DELETE (no permission).
	result, err = e.CheckAccess(ctx, "user-1", "platform", "", "/api/v1/posts/123", "DELETE")
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if result.Allowed {
		t.Error("expected denied for DELETE")
	}
}

func TestCheckAccess_DeepHierarchy(t *testing.T) {
	e, ctx := setupTestEngine(t)

	// Chain: level3 -> level2 -> level1 -> base
	_ = e.CreateRole(ctx, &store.Role{Name: "base"})
	_ = e.AddPermission(ctx, &store.Permission{Role: "base", Resource: "/health", Action: "GET"})

	_ = e.CreateRole(ctx, &store.Role{Name: "level1", Parents: []string{"base"}})
	_ = e.CreateRole(ctx, &store.Role{Name: "level2", Parents: []string{"level1"}})
	_ = e.CreateRole(ctx, &store.Role{Name: "level3", Parents: []string{"level2"}})

	_ = e.AssignRole(ctx, "user-1", "level3", "platform", "")

	result, err := e.CheckAccess(ctx, "user-1", "platform", "", "/health", "GET")
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if !result.Allowed {
		t.Error("expected allowed via deep hierarchy")
	}
	if len(result.EffectiveRoles) != 4 {
		t.Errorf("expected 4 effective roles, got %d: %v", len(result.EffectiveRoles), result.EffectiveRoles)
	}
}

func TestCheckAccess_MultipleRoles(t *testing.T) {
	e, ctx := setupTestEngine(t)

	_ = e.CreateRole(ctx, &store.Role{Name: "reader"})
	_ = e.AddPermission(ctx, &store.Permission{Role: "reader", Resource: "/api/**", Action: "GET"})

	_ = e.CreateRole(ctx, &store.Role{Name: "writer"})
	_ = e.AddPermission(ctx, &store.Permission{Role: "writer", Resource: "/api/**", Action: "POST"})

	_ = e.AssignRole(ctx, "user-1", "reader", "platform", "")
	_ = e.AssignRole(ctx, "user-1", "writer", "platform", "")

	// GET allowed via reader.
	result, _ := e.CheckAccess(ctx, "user-1", "platform", "", "/api/v1/data", "GET")
	if !result.Allowed {
		t.Error("expected GET allowed")
	}

	// POST allowed via writer.
	result, _ = e.CheckAccess(ctx, "user-1", "platform", "", "/api/v1/data", "POST")
	if !result.Allowed {
		t.Error("expected POST allowed")
	}

	// DELETE denied — neither role has it.
	result, _ = e.CheckAccess(ctx, "user-1", "platform", "", "/api/v1/data", "DELETE")
	if result.Allowed {
		t.Error("expected DELETE denied")
	}
}

func TestCheckAccess_ResourcePatterns(t *testing.T) {
	e, ctx := setupTestEngine(t)

	_ = e.CreateRole(ctx, &store.Role{Name: "project-viewer"})
	_ = e.AddPermission(ctx, &store.Permission{
		Role: "project-viewer", Resource: "/api/v1/projects/*", Action: "GET",
	})
	_ = e.AssignRole(ctx, "user-1", "project-viewer", "platform", "")

	// Allowed: single segment after /projects/
	result, _ := e.CheckAccess(ctx, "user-1", "platform", "", "/api/v1/projects/123", "GET")
	if !result.Allowed {
		t.Error("expected allowed for /api/v1/projects/123")
	}

	// Denied: nested path (single wildcard doesn't match multiple segments).
	result, _ = e.CheckAccess(ctx, "user-1", "platform", "", "/api/v1/projects/123/members", "GET")
	if result.Allowed {
		t.Error("expected denied for /api/v1/projects/123/members with single wildcard")
	}

	// Denied: exact /projects (no segment to match wildcard).
	result, _ = e.CheckAccess(ctx, "user-1", "platform", "", "/api/v1/projects", "GET")
	if result.Allowed {
		t.Error("expected denied for /api/v1/projects with single wildcard")
	}
}

func TestEnrichedHeaders(t *testing.T) {
	result := &Result{
		Allowed:        true,
		MatchedRoles:   []string{"editor"},
		EffectiveRoles: []string{"editor", "viewer"},
	}

	headers := EnrichedHeaders(result)

	if headers["X-Authz-Decision"] != "allow" {
		t.Errorf("expected decision=allow, got %q", headers["X-Authz-Decision"])
	}
	if headers["X-User-Roles"] != "editor,viewer" {
		t.Errorf("expected roles=editor,viewer, got %q", headers["X-User-Roles"])
	}
	if headers["X-Authz-Matched-Roles"] != "editor" {
		t.Errorf("expected matched=editor, got %q", headers["X-Authz-Matched-Roles"])
	}
}

func TestEnrichedHeaders_Denied(t *testing.T) {
	result := &Result{Allowed: false}
	headers := EnrichedHeaders(result)

	if headers["X-Authz-Decision"] != "deny" {
		t.Errorf("expected decision=deny, got %q", headers["X-Authz-Decision"])
	}
}

// --- Tenant-scoped tests ---

func TestCheckAccess_TenantScopedRole(t *testing.T) {
	e, ctx := setupTestEngine(t)

	_ = e.CreateRole(ctx, &store.Role{Name: "tenant_viewer"})
	_ = e.AddPermission(ctx, &store.Permission{Role: "tenant_viewer", Resource: "prices", Action: "read"})

	_ = e.AssignRole(ctx, "user-42", "tenant_viewer", "tenant", "tenant-123")

	// Allowed in the assigned tenant.
	result, err := e.CheckAccess(ctx, "user-42", "tenant", "tenant-123", "prices", "read")
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if !result.Allowed {
		t.Error("expected allowed in tenant-123")
	}

	// Denied in a different tenant.
	result, err = e.CheckAccess(ctx, "user-42", "tenant", "tenant-456", "prices", "read")
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if result.Allowed {
		t.Error("expected denied in tenant-456 (cross-tenant isolation)")
	}
}

func TestCheckAccess_PlatformAdminFallback(t *testing.T) {
	e, ctx := setupTestEngine(t)

	_ = e.CreateRole(ctx, &store.Role{Name: "platform_admin"})
	_ = e.AddPermission(ctx, &store.Permission{Role: "platform_admin", Resource: "**", Action: "*"})

	_ = e.AssignRole(ctx, "admin-1", "platform_admin", "platform", "")

	// Platform admin should be allowed in any tenant check.
	result, err := e.CheckAccess(ctx, "admin-1", "tenant", "tenant-999", "prices", "generate")
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if !result.Allowed {
		t.Error("expected platform admin allowed in any tenant")
	}
}

func TestCheckAccess_SameUserDifferentTenantRoles(t *testing.T) {
	e, ctx := setupTestEngine(t)

	_ = e.CreateRole(ctx, &store.Role{Name: "tenant_owner"})
	_ = e.AddPermission(ctx, &store.Permission{Role: "tenant_owner", Resource: "tenant.settings", Action: "manage"})

	_ = e.CreateRole(ctx, &store.Role{Name: "tenant_viewer"})
	_ = e.AddPermission(ctx, &store.Permission{Role: "tenant_viewer", Resource: "prices", Action: "read"})

	// user-42 is owner in tenant-a, viewer in tenant-b
	_ = e.AssignRole(ctx, "user-42", "tenant_owner", "tenant", "tenant-a")
	_ = e.AssignRole(ctx, "user-42", "tenant_viewer", "tenant", "tenant-b")

	// Owner action allowed in tenant-a.
	result, _ := e.CheckAccess(ctx, "user-42", "tenant", "tenant-a", "tenant.settings", "manage")
	if !result.Allowed {
		t.Error("expected owner action allowed in tenant-a")
	}

	// Owner action denied in tenant-b (user is only viewer there).
	result, _ = e.CheckAccess(ctx, "user-42", "tenant", "tenant-b", "tenant.settings", "manage")
	if result.Allowed {
		t.Error("expected owner action denied in tenant-b")
	}

	// Viewer action allowed in tenant-b.
	result, _ = e.CheckAccess(ctx, "user-42", "tenant", "tenant-b", "prices", "read")
	if !result.Allowed {
		t.Error("expected viewer action allowed in tenant-b")
	}

	// Viewer action denied in tenant-a (owner doesn't have prices.read).
	result, _ = e.CheckAccess(ctx, "user-42", "tenant", "tenant-a", "prices", "read")
	if result.Allowed {
		t.Error("expected viewer action denied in tenant-a (owner lacks prices.read)")
	}
}

func TestCheckAccess_PlatformPlusTenantRolesMerge(t *testing.T) {
	e, ctx := setupTestEngine(t)

	_ = e.CreateRole(ctx, &store.Role{Name: "platform_manager"})
	_ = e.AddPermission(ctx, &store.Permission{Role: "platform_manager", Resource: "analytics", Action: "read"})

	_ = e.CreateRole(ctx, &store.Role{Name: "tenant_member"})
	_ = e.AddPermission(ctx, &store.Permission{Role: "tenant_member", Resource: "prices", Action: "generate"})

	// User has platform role + tenant role.
	_ = e.AssignRole(ctx, "user-10", "platform_manager", "platform", "")
	_ = e.AssignRole(ctx, "user-10", "tenant_member", "tenant", "t1")

	// Platform permission should work in tenant context.
	result, _ := e.CheckAccess(ctx, "user-10", "tenant", "t1", "analytics", "read")
	if !result.Allowed {
		t.Error("expected platform_manager analytics.read allowed in tenant context")
	}

	// Tenant permission should also work.
	result, _ = e.CheckAccess(ctx, "user-10", "tenant", "t1", "prices", "generate")
	if !result.Allowed {
		t.Error("expected tenant_member prices.generate allowed")
	}
}

func TestMergeUnique(t *testing.T) {
	result := mergeUnique([]string{"a", "b", "c"}, []string{"b", "c", "d"})
	if len(result) != 4 {
		t.Fatalf("expected 4 unique items, got %d: %v", len(result), result)
	}

	expected := map[string]bool{"a": true, "b": true, "c": true, "d": true}
	for _, s := range result {
		if !expected[s] {
			t.Errorf("unexpected item %q", s)
		}
	}
}
