// Package store defines the persistence interface for csar-authz.
//
// The Store interface abstracts role, permission, and assignment storage,
// allowing implementations for in-memory, PostgreSQL, etc.
package store

import (
	"context"
	"errors"
	"time"
)

// Sentinel errors returned by Store implementations.
var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
	ErrRoleInUse     = errors.New("role is assigned to subjects")
)

// Role represents a named authorization role with optional parent hierarchy.
type Role struct {
	Name        string
	Description string
	Parents     []string
	CreatedAt   time.Time
}

// Permission represents an allowed action on a resource pattern.
type Permission struct {
	ID       string // unique identifier
	Role     string // owning role name
	Resource string // URL pattern (supports * and ** wildcards)
	Action   string // HTTP method or "*" for any
}

// ScopedAssignment represents a subject-role binding within a scope.
type ScopedAssignment struct {
	Subject   string
	Role      string
	ScopeType string // "platform" or "tenant"
	ScopeID   string // "" for platform, tenant identifier for tenant
}

// SubjectScope represents a distinct scope where a subject has assignments.
type SubjectScope struct {
	ScopeType string
	ScopeID   string
}

// Store defines the persistence contract for csar-authz.
// Implementations must be safe for concurrent use.
type Store interface {
	// --- Roles ---

	// CreateRole inserts a new role. Returns ErrAlreadyExists if the name is taken.
	CreateRole(ctx context.Context, role *Role) error

	// GetRole returns a role by name. Returns ErrNotFound if absent.
	GetRole(ctx context.Context, name string) (*Role, error)

	// DeleteRole removes a role. Returns ErrNotFound if absent.
	// Implementations should also remove all permissions and assignments for the role.
	DeleteRole(ctx context.Context, name string) error

	// ListRoles returns all defined roles.
	ListRoles(ctx context.Context) ([]*Role, error)

	// --- Subject-Role Assignments ---

	// AssignRole grants a role to a subject within a scope. No-op if already assigned.
	// Returns ErrNotFound if the role does not exist.
	AssignRole(ctx context.Context, subject, role, scopeType, scopeID string) error

	// RevokeRole removes a role from a subject within a scope. No-op if not assigned.
	RevokeRole(ctx context.Context, subject, role, scopeType, scopeID string) error

	// GetSubjectRoles returns all directly assigned role names for a subject within a scope.
	GetSubjectRoles(ctx context.Context, subject, scopeType, scopeID string) ([]string, error)

	// --- Scope Queries ---

	// ListScopeAssignments returns all assignments within a given scope.
	ListScopeAssignments(ctx context.Context, scopeType, scopeID string) ([]ScopedAssignment, error)

	// ListSubjectScopes returns all distinct (scope_type, scope_id) pairs where a subject has assignments.
	ListSubjectScopes(ctx context.Context, subject string) ([]SubjectScope, error)

	// ListTenants returns all distinct tenant scope IDs that have at least one assignment.
	ListTenants(ctx context.Context) ([]string, error)

	// --- Bulk Operations ---

	// SyncPolicy atomically replaces roles and permissions from config.
	// Assignments are preserved for roles that still exist; assignments
	// referencing removed roles are deleted.
	SyncPolicy(ctx context.Context, roles []*Role, perms []*Permission) error

	// Deprecated: Sync atomically replaces all roles, permissions, and
	// assignments. Use SyncPolicy for production startup/reload paths —
	// Sync wipes runtime assignments and should only be used in tests.
	Sync(ctx context.Context, roles []*Role, perms []*Permission, assignments []ScopedAssignment) error

	// --- Permissions ---

	// AddPermission adds a permission to a role. Returns ErrNotFound if the role doesn't exist.
	AddPermission(ctx context.Context, perm *Permission) error

	// RemovePermission removes a permission by ID. Returns ErrNotFound if absent.
	RemovePermission(ctx context.Context, id string) error

	// GetRolePermissions returns all permissions for a given role.
	GetRolePermissions(ctx context.Context, role string) ([]*Permission, error)
}
