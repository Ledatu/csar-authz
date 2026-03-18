// Package engine implements the RBAC authorization evaluation engine.
//
// The engine evaluates access decisions by resolving a subject's roles
// (including inherited parent roles) and checking their permissions
// against the requested resource and action.
package engine

import (
	"context"
	"strings"

	"github.com/ledatu/csar-authz/internal/store"
)

// maxHierarchyDepth prevents infinite loops in cyclic role hierarchies.
const maxHierarchyDepth = 32

// Result holds the outcome of an access check.
type Result struct {
	Allowed        bool
	MatchedRoles   []string
	EffectiveRoles []string
}

// Engine evaluates RBAC access decisions against a policy store.
type Engine struct {
	store store.Store
}

// New creates a new Engine backed by the given store.
func New(s store.Store) *Engine {
	return &Engine{store: s}
}

// CheckAccess evaluates whether a subject can perform an action on a resource
// within a given scope.
//
// Algorithm:
//  1. Always fetch platform-scoped roles for the subject.
//  2. If the scope is tenant, also fetch tenant-scoped roles and merge.
//  3. Expand role hierarchy by collecting all parent roles (with cycle detection).
//  4. For each effective role, check if any permission matches (resource + action).
//  5. Return the result with matched roles and effective roles.
func (e *Engine) CheckAccess(ctx context.Context, subject, scopeType, scopeID, resource, action string) (*Result, error) {
	// 1. Always get platform roles.
	platformRoles, err := e.store.GetSubjectRoles(ctx, subject, "platform", "")
	if err != nil {
		return nil, err
	}

	// 2. If tenant scope, also fetch tenant roles and merge.
	directRoles := platformRoles
	if scopeType == "tenant" && scopeID != "" {
		tenantRoles, err := e.store.GetSubjectRoles(ctx, subject, "tenant", scopeID)
		if err != nil {
			return nil, err
		}
		directRoles = mergeUnique(platformRoles, tenantRoles)
	}

	if len(directRoles) == 0 {
		return &Result{Allowed: false}, nil
	}

	// 3. Expand role hierarchy.
	effectiveRoles, err := e.expandRoles(ctx, directRoles)
	if err != nil {
		return nil, err
	}

	// 4. Check permissions for each effective role.
	var matchedRoles []string
	for _, role := range effectiveRoles {
		perms, err := e.store.GetRolePermissions(ctx, role)
		if err != nil {
			return nil, err
		}

		for _, perm := range perms {
			if MatchResource(perm.Resource, resource) && MatchAction(perm.Action, action) {
				matchedRoles = append(matchedRoles, role)
				break
			}
		}
	}

	return &Result{
		Allowed:        len(matchedRoles) > 0,
		MatchedRoles:   matchedRoles,
		EffectiveRoles: effectiveRoles,
	}, nil
}

// mergeUnique combines two string slices, removing duplicates.
func mergeUnique(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	result := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}
	for _, s := range b {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}
	return result
}

// expandRoles resolves a list of role names into the full set of effective roles,
// traversing the parent hierarchy with cycle detection.
func (e *Engine) expandRoles(ctx context.Context, roles []string) ([]string, error) {
	visited := make(map[string]struct{})
	var result []string

	var walk func(name string, depth int) error
	walk = func(name string, depth int) error {
		if depth > maxHierarchyDepth {
			return nil // stop at max depth to prevent runaway
		}
		if _, seen := visited[name]; seen {
			return nil
		}
		visited[name] = struct{}{}
		result = append(result, name)

		role, err := e.store.GetRole(ctx, name)
		if err != nil {
			return nil // role might have been deleted concurrently; skip
		}

		for _, parent := range role.Parents {
			if err := walk(parent, depth+1); err != nil {
				return err
			}
		}
		return nil
	}

	for _, r := range roles {
		if err := walk(r, 0); err != nil {
			return nil, err
		}
	}

	return result, nil
}

// EnrichedHeaders builds the header map to inject into upstream requests.
func EnrichedHeaders(result *Result) map[string]string {
	headers := make(map[string]string)

	if result.Allowed {
		headers["X-Authz-Decision"] = "allow"
	} else {
		headers["X-Authz-Decision"] = "deny"
	}

	if len(result.EffectiveRoles) > 0 {
		headers["X-User-Roles"] = strings.Join(result.EffectiveRoles, ",")
	}

	if len(result.MatchedRoles) > 0 {
		headers["X-Authz-Matched-Roles"] = strings.Join(result.MatchedRoles, ",")
	}

	return headers
}

// --- Delegated store operations (for the gRPC server layer) ---

// CreateRole delegates to the store.
func (e *Engine) CreateRole(ctx context.Context, role *store.Role) error {
	return e.store.CreateRole(ctx, role)
}

// GetRole delegates to the store.
func (e *Engine) GetRole(ctx context.Context, name string) (*store.Role, error) {
	return e.store.GetRole(ctx, name)
}

// DeleteRole delegates to the store.
func (e *Engine) DeleteRole(ctx context.Context, name string) error {
	return e.store.DeleteRole(ctx, name)
}

// ListRoles delegates to the store.
func (e *Engine) ListRoles(ctx context.Context) ([]*store.Role, error) {
	return e.store.ListRoles(ctx)
}

// AssignRole delegates to the store.
func (e *Engine) AssignRole(ctx context.Context, subject, role, scopeType, scopeID string) error {
	return e.store.AssignRole(ctx, subject, role, scopeType, scopeID)
}

// RevokeRole delegates to the store.
func (e *Engine) RevokeRole(ctx context.Context, subject, role, scopeType, scopeID string) error {
	return e.store.RevokeRole(ctx, subject, role, scopeType, scopeID)
}

// ListSubjectRoles delegates to the store.
func (e *Engine) ListSubjectRoles(ctx context.Context, subject, scopeType, scopeID string) ([]string, error) {
	return e.store.GetSubjectRoles(ctx, subject, scopeType, scopeID)
}

// ExpandRoles resolves a list of role names into the full set of effective roles
// (including inherited parents). Exported for use by the admin HTTP layer.
func (e *Engine) ExpandRoles(ctx context.Context, roles []string) ([]string, error) {
	return e.expandRoles(ctx, roles)
}

// ListScopeAssignments delegates to the store.
func (e *Engine) ListScopeAssignments(ctx context.Context, scopeType, scopeID string) ([]store.ScopedAssignment, error) {
	return e.store.ListScopeAssignments(ctx, scopeType, scopeID)
}

// ListSubjectScopes delegates to the store.
func (e *Engine) ListSubjectScopes(ctx context.Context, subject string) ([]store.SubjectScope, error) {
	return e.store.ListSubjectScopes(ctx, subject)
}

// ListTenants delegates to the store.
func (e *Engine) ListTenants(ctx context.Context) ([]string, error) {
	return e.store.ListTenants(ctx)
}

// AddPermission delegates to the store.
func (e *Engine) AddPermission(ctx context.Context, perm *store.Permission) error {
	return e.store.AddPermission(ctx, perm)
}

// RemovePermission delegates to the store.
func (e *Engine) RemovePermission(ctx context.Context, id string) error {
	return e.store.RemovePermission(ctx, id)
}

// ListRolePermissions delegates to the store.
func (e *Engine) ListRolePermissions(ctx context.Context, role string) ([]*store.Permission, error) {
	return e.store.GetRolePermissions(ctx, role)
}
