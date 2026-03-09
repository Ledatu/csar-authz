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

	// AssignRole grants a role to a subject. No-op if already assigned.
	// Returns ErrNotFound if the role does not exist.
	AssignRole(ctx context.Context, subject, role string) error

	// RevokeRole removes a role from a subject. No-op if not assigned.
	RevokeRole(ctx context.Context, subject, role string) error

	// GetSubjectRoles returns all directly assigned role names for a subject.
	GetSubjectRoles(ctx context.Context, subject string) ([]string, error)

	// --- Permissions ---

	// AddPermission adds a permission to a role. Returns ErrNotFound if the role doesn't exist.
	AddPermission(ctx context.Context, perm *Permission) error

	// RemovePermission removes a permission by ID. Returns ErrNotFound if absent.
	RemovePermission(ctx context.Context, id string) error

	// GetRolePermissions returns all permissions for a given role.
	GetRolePermissions(ctx context.Context, role string) ([]*Permission, error)
}
