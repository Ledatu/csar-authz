// Package memory provides an in-memory implementation of the store.Store interface.
//
// Suitable for development, testing, and single-instance deployments.
// All data is lost on process restart.
package memory

import (
	"cmp"
	"context"
	"fmt"
	"slices"
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

type assignmentKey struct {
	Subject   string
	ScopeType string
	ScopeID   string
}

// Store is a thread-safe in-memory implementation of store.Store.
type Store struct {
	mu sync.RWMutex

	// roles maps role name → Role.
	roles map[string]*store.Role

	// assignments maps (subject, scopeType, scopeID) → set of role names.
	assignments map[assignmentKey]map[string]struct{}

	// permissions maps role name → slice of permissions.
	permissions map[string][]*store.Permission

	// permByID maps permission ID → permission (for fast removal).
	permByID map[string]*store.Permission
}

// New creates a new in-memory store.
func New() *Store {
	return &Store{
		roles:       make(map[string]*store.Role),
		assignments: make(map[assignmentKey]map[string]struct{}),
		permissions: make(map[string][]*store.Permission),
		permByID:    make(map[string]*store.Permission),
	}
}

// SyncPolicy atomically replaces roles and permissions while preserving
// runtime assignments. Assignments referencing removed roles are pruned.
func (s *Store) SyncPolicy(_ context.Context, roles []*store.Role, perms []*store.Permission) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	newRoles := make(map[string]*store.Role, len(roles))
	for _, r := range roles {
		for _, parent := range r.Parents {
			if _, ok := newRoles[parent]; !ok {
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
		newRoles[cp.Name] = &cp
	}

	newPerms := make(map[string][]*store.Permission)
	newPermByID := make(map[string]*store.Permission)
	for _, p := range perms {
		if _, ok := newRoles[p.Role]; !ok {
			return fmt.Errorf("permission role %q: %w", p.Role, store.ErrNotFound)
		}
		cp := *p
		if cp.ID == "" {
			cp.ID = nextPermID()
		}
		newPerms[cp.Role] = append(newPerms[cp.Role], &cp)
		newPermByID[cp.ID] = &cp
	}

	// Prune assignments referencing roles that no longer exist.
	for key, roleSet := range s.assignments {
		for roleName := range roleSet {
			if _, ok := newRoles[roleName]; !ok {
				delete(roleSet, roleName)
			}
		}
		if len(roleSet) == 0 {
			delete(s.assignments, key)
		}
	}

	s.roles = newRoles
	s.permissions = newPerms
	s.permByID = newPermByID
	return nil
}

// Sync atomically replaces all roles, permissions, and assignments.
func (s *Store) Sync(_ context.Context, roles []*store.Role, perms []*store.Permission, assignments []store.ScopedAssignment) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Clear all state.
	s.roles = make(map[string]*store.Role, len(roles))
	s.assignments = make(map[assignmentKey]map[string]struct{})
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
	for _, a := range assignments {
		if _, ok := s.roles[a.Role]; !ok {
			return fmt.Errorf("assignment role %q for subject %q: %w", a.Role, a.Subject, store.ErrNotFound)
		}
		key := assignmentKey{Subject: a.Subject, ScopeType: a.ScopeType, ScopeID: a.ScopeID}
		if s.assignments[key] == nil {
			s.assignments[key] = make(map[string]struct{})
		}
		s.assignments[key][a.Role] = struct{}{}
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
	for key, roles := range s.assignments {
		delete(roles, name)
		if len(roles) == 0 {
			delete(s.assignments, key)
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

// AssignRole grants a role to a subject within a scope.
func (s *Store) AssignRole(_ context.Context, subject, role, scopeType, scopeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.roles[role]; !exists {
		return fmt.Errorf("role %q: %w", role, store.ErrNotFound)
	}

	key := assignmentKey{Subject: subject, ScopeType: scopeType, ScopeID: scopeID}
	if s.assignments[key] == nil {
		s.assignments[key] = make(map[string]struct{})
	}
	s.assignments[key][role] = struct{}{}
	return nil
}

// RevokeRole removes a role from a subject within a scope.
func (s *Store) RevokeRole(_ context.Context, subject, role, scopeType, scopeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := assignmentKey{Subject: subject, ScopeType: scopeType, ScopeID: scopeID}
	if roles, ok := s.assignments[key]; ok {
		delete(roles, role)
		if len(roles) == 0 {
			delete(s.assignments, key)
		}
	}
	return nil
}

// GetSubjectRoles returns all directly assigned role names within a scope.
func (s *Store) GetSubjectRoles(_ context.Context, subject, scopeType, scopeID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := assignmentKey{Subject: subject, ScopeType: scopeType, ScopeID: scopeID}
	roles, ok := s.assignments[key]
	if !ok {
		return nil, nil
	}

	result := make([]string, 0, len(roles))
	for r := range roles {
		result = append(result, r)
	}
	slices.Sort(result)
	return result, nil
}

// ListScopeAssignments returns all assignments within a given scope.
func (s *Store) ListScopeAssignments(_ context.Context, scopeType, scopeID string) ([]store.ScopedAssignment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []store.ScopedAssignment
	for key, roles := range s.assignments {
		if key.ScopeType == scopeType && key.ScopeID == scopeID {
			for role := range roles {
				result = append(result, store.ScopedAssignment{
					Subject:   key.Subject,
					Role:      role,
					ScopeType: key.ScopeType,
					ScopeID:   key.ScopeID,
				})
			}
		}
	}
	slices.SortFunc(result, func(a, b store.ScopedAssignment) int {
		if c := cmp.Compare(a.Subject, b.Subject); c != 0 {
			return c
		}
		return cmp.Compare(a.Role, b.Role)
	})
	return result, nil
}

// ListSubjectScopes returns all distinct scopes where a subject has assignments.
func (s *Store) ListSubjectScopes(_ context.Context, subject string) ([]store.SubjectScope, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	seen := make(map[store.SubjectScope]struct{})
	var result []store.SubjectScope
	for key := range s.assignments {
		if key.Subject == subject {
			sc := store.SubjectScope{ScopeType: key.ScopeType, ScopeID: key.ScopeID}
			if _, ok := seen[sc]; !ok {
				seen[sc] = struct{}{}
				result = append(result, sc)
			}
		}
	}
	slices.SortFunc(result, func(a, b store.SubjectScope) int {
		if c := cmp.Compare(a.ScopeType, b.ScopeType); c != 0 {
			return c
		}
		return cmp.Compare(a.ScopeID, b.ScopeID)
	})
	return result, nil
}

// ListTenants returns all distinct tenant scope IDs that have at least one assignment.
func (s *Store) ListTenants(_ context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	seen := make(map[string]struct{})
	var result []string
	for key := range s.assignments {
		if key.ScopeType == "tenant" && key.ScopeID != "" {
			if _, ok := seen[key.ScopeID]; !ok {
				seen[key.ScopeID] = struct{}{}
				result = append(result, key.ScopeID)
			}
		}
	}
	slices.Sort(result)
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
