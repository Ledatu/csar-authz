// Package memory provides an in-memory implementation of the store.Store interface.
//
// Suitable for development, testing, and single-instance deployments.
// All data is lost on process restart.
package memory

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ledatu/csar-authz/internal/store"
)

// permIDCounter generates unique permission IDs.
var permIDCounter atomic.Uint64

func nextPermID() string {
	return fmt.Sprintf("perm_%d", permIDCounter.Add(1))
}

// Store is a thread-safe in-memory implementation of store.Store.
type Store struct {
	mu sync.RWMutex

	// roles maps role name → Role.
	roles map[string]*store.Role

	// assignments maps subject → set of role names.
	assignments map[string]map[string]struct{}

	// permissions maps role name → slice of permissions.
	permissions map[string][]*store.Permission

	// permByID maps permission ID → permission (for fast removal).
	permByID map[string]*store.Permission
}

// New creates a new in-memory store.
func New() *Store {
	return &Store{
		roles:       make(map[string]*store.Role),
		assignments: make(map[string]map[string]struct{}),
		permissions: make(map[string][]*store.Permission),
		permByID:    make(map[string]*store.Permission),
	}
}

// Sync atomically replaces all roles, permissions, and assignments.
func (s *Store) Sync(_ context.Context, roles []*store.Role, perms []*store.Permission, assignments map[string][]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Clear all state.
	s.roles = make(map[string]*store.Role, len(roles))
	s.assignments = make(map[string]map[string]struct{})
	s.permissions = make(map[string][]*store.Permission)
	s.permByID = make(map[string]*store.Permission)

	// Insert roles (caller ensures parents come before children).
	for _, r := range roles {
		for _, parent := range r.Parents {
			if _, ok := s.roles[parent]; !ok {
				return fmt.Errorf("parent role %q: %w", parent, store.ErrNotFound)
			}
		}
		cp := *r
		parents := make([]string, len(r.Parents))
		copy(parents, r.Parents)
		cp.Parents = parents
		if cp.CreatedAt.IsZero() {
			cp.CreatedAt = time.Now()
		}
		s.roles[cp.Name] = &cp
	}

	// Insert permissions.
	for _, p := range perms {
		if _, ok := s.roles[p.Role]; !ok {
			return fmt.Errorf("permission role %q: %w", p.Role, store.ErrNotFound)
		}
		cp := *p
		if cp.ID == "" {
			cp.ID = nextPermID()
		}
		s.permissions[cp.Role] = append(s.permissions[cp.Role], &cp)
		s.permByID[cp.ID] = &cp
	}

	// Insert assignments.
	for subject, roleNames := range assignments {
		for _, roleName := range roleNames {
			if _, ok := s.roles[roleName]; !ok {
				return fmt.Errorf("assignment role %q for subject %q: %w", roleName, subject, store.ErrNotFound)
			}
			if s.assignments[subject] == nil {
				s.assignments[subject] = make(map[string]struct{})
			}
			s.assignments[subject][roleName] = struct{}{}
		}
	}

	return nil
}

// CreateRole inserts a new role.
func (s *Store) CreateRole(_ context.Context, role *store.Role) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.roles[role.Name]; exists {
		return store.ErrAlreadyExists
	}

	// Validate parent roles exist.
	for _, parent := range role.Parents {
		if _, exists := s.roles[parent]; !exists {
			return fmt.Errorf("parent role %q: %w", parent, store.ErrNotFound)
		}
	}

	// Copy to prevent caller mutation.
	stored := *role
	if stored.CreatedAt.IsZero() {
		stored.CreatedAt = time.Now()
	}
	parents := make([]string, len(role.Parents))
	copy(parents, role.Parents)
	stored.Parents = parents

	s.roles[role.Name] = &stored
	return nil
}

// GetRole returns a role by name.
func (s *Store) GetRole(_ context.Context, name string) (*store.Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	r, ok := s.roles[name]
	if !ok {
		return nil, store.ErrNotFound
	}

	// Return a copy.
	cp := *r
	parents := make([]string, len(r.Parents))
	copy(parents, r.Parents)
	cp.Parents = parents
	return &cp, nil
}

// DeleteRole removes a role and all its permissions and assignments.
func (s *Store) DeleteRole(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.roles[name]; !exists {
		return store.ErrNotFound
	}

	// Remove permissions.
	for _, perm := range s.permissions[name] {
		delete(s.permByID, perm.ID)
	}
	delete(s.permissions, name)

	// Remove assignments.
	for subj, roles := range s.assignments {
		delete(roles, name)
		if len(roles) == 0 {
			delete(s.assignments, subj)
		}
	}

	// Remove from parent references in other roles.
	for _, r := range s.roles {
		filtered := r.Parents[:0]
		for _, p := range r.Parents {
			if p != name {
				filtered = append(filtered, p)
			}
		}
		r.Parents = filtered
	}

	delete(s.roles, name)
	return nil
}

// ListRoles returns all defined roles.
func (s *Store) ListRoles(_ context.Context) ([]*store.Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*store.Role, 0, len(s.roles))
	for _, r := range s.roles {
		cp := *r
		parents := make([]string, len(r.Parents))
		copy(parents, r.Parents)
		cp.Parents = parents
		result = append(result, &cp)
	}
	return result, nil
}

// AssignRole grants a role to a subject.
func (s *Store) AssignRole(_ context.Context, subject, role string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.roles[role]; !exists {
		return fmt.Errorf("role %q: %w", role, store.ErrNotFound)
	}

	if s.assignments[subject] == nil {
		s.assignments[subject] = make(map[string]struct{})
	}
	s.assignments[subject][role] = struct{}{}
	return nil
}

// RevokeRole removes a role from a subject.
func (s *Store) RevokeRole(_ context.Context, subject, role string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if roles, ok := s.assignments[subject]; ok {
		delete(roles, role)
		if len(roles) == 0 {
			delete(s.assignments, subject)
		}
	}
	return nil
}

// GetSubjectRoles returns all directly assigned role names.
func (s *Store) GetSubjectRoles(_ context.Context, subject string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	roles, ok := s.assignments[subject]
	if !ok {
		return nil, nil
	}

	result := make([]string, 0, len(roles))
	for r := range roles {
		result = append(result, r)
	}
	return result, nil
}

// AddPermission adds a permission to a role.
func (s *Store) AddPermission(_ context.Context, perm *store.Permission) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.roles[perm.Role]; !exists {
		return fmt.Errorf("role %q: %w", perm.Role, store.ErrNotFound)
	}

	// Assign ID if not set.
	if perm.ID == "" {
		perm.ID = nextPermID()
	}
	stored := *perm

	s.permissions[perm.Role] = append(s.permissions[perm.Role], &stored)
	s.permByID[stored.ID] = &stored
	return nil
}

// RemovePermission removes a permission by ID.
func (s *Store) RemovePermission(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	perm, ok := s.permByID[id]
	if !ok {
		return store.ErrNotFound
	}

	// Remove from role's permission list.
	perms := s.permissions[perm.Role]
	for i, p := range perms {
		if p.ID == id {
			s.permissions[perm.Role] = append(perms[:i], perms[i+1:]...)
			break
		}
	}

	delete(s.permByID, id)
	return nil
}

// GetRolePermissions returns all permissions for a role.
func (s *Store) GetRolePermissions(_ context.Context, role string) ([]*store.Permission, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	perms := s.permissions[role]
	result := make([]*store.Permission, len(perms))
	for i, p := range perms {
		cp := *p
		result[i] = &cp
	}
	return result, nil
}
