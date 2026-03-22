// Package postgres implements the store.Store interface for csar-authz using PostgreSQL.
package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ledatu/csar-authz/internal/store"
	"github.com/ledatu/csar-core/pgutil"
)

// Store implements store.Store backed by PostgreSQL.
type Store struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// Option configures the PostgreSQL store.
type Option func(*Store)

// WithLogger sets the logger.
func WithLogger(l *slog.Logger) Option {
	return func(s *Store) { s.logger = l }
}

// New creates a new PostgreSQL-backed authz store and verifies connectivity.
func New(ctx context.Context, dsn string, opts ...Option) (*Store, error) {
	s := &Store{
		logger: slog.Default(),
	}
	for _, opt := range opts {
		opt(s)
	}

	pool, err := pgutil.NewPool(ctx, dsn, pgutil.WithLogger(s.logger))
	if err != nil {
		return nil, err
	}
	s.pool = pool

	return s, nil
}

// Migrate runs schema migrations.
func (s *Store) Migrate(ctx context.Context) error {
	return pgutil.RunMigrations(ctx, s.pool, "authz_schema_migrations", migrations, s.logger)
}

// Close releases the connection pool.
func (s *Store) Close() {
	s.pool.Close()
}

// Pool returns the underlying pgxpool.Pool for shared use by other components.
func (s *Store) Pool() *pgxpool.Pool {
	return s.pool
}

// --- Roles ---

func (s *Store) CreateRole(ctx context.Context, role *store.Role) error {
	return pgutil.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		if role.CreatedAt.IsZero() {
			role.CreatedAt = time.Now()
		}

		_, err := tx.Exec(ctx,
			`INSERT INTO roles (name, description, created_at) VALUES ($1, $2, $3)`,
			role.Name, role.Description, role.CreatedAt,
		)
		if err != nil {
			if pgutil.IsDuplicateKey(err) {
				return store.ErrAlreadyExists
			}
			return fmt.Errorf("inserting role: %w", err)
		}

		for _, parent := range role.Parents {
			_, err := tx.Exec(ctx,
				`INSERT INTO role_parents (role_name, parent_name) VALUES ($1, $2)`,
				role.Name, parent,
			)
			if err != nil {
				return fmt.Errorf("inserting role parent %q: %w", parent, err)
			}
		}

		return nil
	})
}

func (s *Store) GetRole(ctx context.Context, name string) (*store.Role, error) {
	r := &store.Role{}
	err := s.pool.QueryRow(ctx,
		`SELECT name, description, created_at FROM roles WHERE name = $1`, name,
	).Scan(&r.Name, &r.Description, &r.CreatedAt)
	if pgutil.IsNotFound(err) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get role: %w", err)
	}

	parents, err := s.getRoleParents(ctx, name)
	if err != nil {
		return nil, err
	}
	r.Parents = parents

	return r, nil
}

func (s *Store) DeleteRole(ctx context.Context, name string) error {
	return pgutil.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`DELETE FROM role_parents WHERE parent_name = $1`, name,
		)
		if err != nil {
			return fmt.Errorf("removing parent references: %w", err)
		}

		tag, err := tx.Exec(ctx, `DELETE FROM roles WHERE name = $1`, name)
		if err != nil {
			return fmt.Errorf("deleting role: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return store.ErrNotFound
		}
		return nil
	})
}

func (s *Store) ListRoles(ctx context.Context) ([]*store.Role, error) {
	rows, err := s.pool.Query(ctx, `SELECT name, description, created_at FROM roles ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("listing roles: %w", err)
	}
	defer rows.Close()

	var roles []*store.Role
	for rows.Next() {
		r := &store.Role{}
		if err := rows.Scan(&r.Name, &r.Description, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning role: %w", err)
		}
		roles = append(roles, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Batch-fetch all parent relationships to avoid N+1 queries.
	parentMap, err := s.getAllRoleParents(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range roles {
		r.Parents = parentMap[r.Name]
	}

	return roles, nil
}

// --- Subject-Role Assignments ---

func (s *Store) AssignRole(ctx context.Context, subject, role, scopeType, scopeID string) error {
	tag, err := s.pool.Exec(ctx,
		`INSERT INTO assignments (subject, role, scope_type, scope_id)
		 SELECT $1, $2, $3, $4 WHERE EXISTS (SELECT 1 FROM roles WHERE name = $2)
		 ON CONFLICT DO NOTHING`,
		subject, role, scopeType, scopeID,
	)
	if err != nil {
		return fmt.Errorf("assigning role: %w", err)
	}
	if tag.RowsAffected() == 0 {
		var roleExists bool
		_ = s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM roles WHERE name = $1)`, role).Scan(&roleExists)
		if !roleExists {
			return fmt.Errorf("role %q: %w", role, store.ErrNotFound)
		}
	}
	return nil
}

func (s *Store) RevokeRole(ctx context.Context, subject, role, scopeType, scopeID string) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM assignments WHERE subject = $1 AND role = $2 AND scope_type = $3 AND scope_id = $4`,
		subject, role, scopeType, scopeID,
	)
	if err != nil {
		return fmt.Errorf("revoking role: %w", err)
	}
	return nil
}

func (s *Store) GetSubjectRoles(ctx context.Context, subject, scopeType, scopeID string) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT role FROM assignments WHERE subject = $1 AND scope_type = $2 AND scope_id = $3 ORDER BY role`,
		subject, scopeType, scopeID,
	)
	if err != nil {
		return nil, fmt.Errorf("getting subject roles: %w", err)
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, fmt.Errorf("scanning role: %w", err)
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

// --- Scope Queries ---

func (s *Store) ListScopeAssignments(ctx context.Context, scopeType, scopeID string) ([]store.ScopedAssignment, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT subject, role, scope_type, scope_id FROM assignments WHERE scope_type = $1 AND scope_id = $2 ORDER BY subject, role`,
		scopeType, scopeID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing scope assignments: %w", err)
	}
	defer rows.Close()

	var assignments []store.ScopedAssignment
	for rows.Next() {
		var a store.ScopedAssignment
		if err := rows.Scan(&a.Subject, &a.Role, &a.ScopeType, &a.ScopeID); err != nil {
			return nil, fmt.Errorf("scanning assignment: %w", err)
		}
		assignments = append(assignments, a)
	}
	return assignments, rows.Err()
}

func (s *Store) ListSubjectScopes(ctx context.Context, subject string) ([]store.SubjectScope, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT DISTINCT scope_type, scope_id FROM assignments WHERE subject = $1 ORDER BY scope_type, scope_id`,
		subject,
	)
	if err != nil {
		return nil, fmt.Errorf("listing subject scopes: %w", err)
	}
	defer rows.Close()

	var scopes []store.SubjectScope
	for rows.Next() {
		var sc store.SubjectScope
		if err := rows.Scan(&sc.ScopeType, &sc.ScopeID); err != nil {
			return nil, fmt.Errorf("scanning scope: %w", err)
		}
		scopes = append(scopes, sc)
	}
	return scopes, rows.Err()
}

// --- Tenant Discovery ---

func (s *Store) ListTenants(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT DISTINCT scope_id FROM assignments WHERE scope_type = 'tenant' AND scope_id != '' ORDER BY scope_id`,
	)
	if err != nil {
		return nil, fmt.Errorf("listing tenants: %w", err)
	}
	defer rows.Close()

	var tenants []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scanning tenant: %w", err)
		}
		tenants = append(tenants, id)
	}
	return tenants, rows.Err()
}

// --- Permissions ---

func (s *Store) AddPermission(ctx context.Context, perm *store.Permission) error {
	if perm.ID == "" {
		perm.ID = uuid.New().String()
	}

	tag, err := s.pool.Exec(ctx,
		`INSERT INTO permissions (id, role, resource, action)
		 SELECT $1, $2, $3, $4 WHERE EXISTS (SELECT 1 FROM roles WHERE name = $2)`,
		perm.ID, perm.Role, perm.Resource, perm.Action,
	)
	if err != nil {
		return fmt.Errorf("adding permission: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("role %q: %w", perm.Role, store.ErrNotFound)
	}
	return nil
}

func (s *Store) RemovePermission(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM permissions WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("removing permission: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) GetRolePermissions(ctx context.Context, role string) ([]*store.Permission, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, role, resource, action FROM permissions WHERE role = $1 ORDER BY id`, role,
	)
	if err != nil {
		return nil, fmt.Errorf("getting role permissions: %w", err)
	}
	defer rows.Close()

	var perms []*store.Permission
	for rows.Next() {
		p := &store.Permission{}
		if err := rows.Scan(&p.ID, &p.Role, &p.Resource, &p.Action); err != nil {
			return nil, fmt.Errorf("scanning permission: %w", err)
		}
		perms = append(perms, p)
	}
	return perms, rows.Err()
}

// --- Bulk Operations ---

// SyncPolicy atomically replaces roles and permissions while preserving
// runtime assignments. Roles are upserted and obsolete roles are pruned;
// ON DELETE CASCADE cleans up assignments only for removed roles.
func (s *Store) SyncPolicy(ctx context.Context, roles []*store.Role, perms []*store.Permission) error {
	return pgutil.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		// Phase 1: clear config-owned tables that do NOT cascade to assignments.
		if _, err := tx.Exec(ctx, `DELETE FROM permissions`); err != nil {
			return fmt.Errorf("clearing permissions: %w", err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM role_parents`); err != nil {
			return fmt.Errorf("clearing role_parents: %w", err)
		}

		// Phase 2: upsert roles — surviving rows are updated in place,
		// so ON DELETE CASCADE is never triggered for them.
		for _, r := range roles {
			createdAt := r.CreatedAt
			if createdAt.IsZero() {
				createdAt = time.Now()
			}
			_, err := tx.Exec(ctx,
				`INSERT INTO roles (name, description, created_at) VALUES ($1, $2, $3)
				 ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description`,
				r.Name, r.Description, createdAt,
			)
			if err != nil {
				return fmt.Errorf("upserting role %q: %w", r.Name, err)
			}
		}

		// Phase 3: prune obsolete roles. CASCADE deletes their assignments,
		// which is correct — those roles no longer exist.
		names := make([]string, len(roles))
		for i, r := range roles {
			names[i] = r.Name
		}
		if _, err := tx.Exec(ctx,
			`DELETE FROM roles WHERE NOT (name = ANY($1::text[]))`, names,
		); err != nil {
			return fmt.Errorf("pruning obsolete roles: %w", err)
		}

		// Phase 4: re-insert role_parents and permissions.
		for _, r := range roles {
			for _, parent := range r.Parents {
				_, err := tx.Exec(ctx,
					`INSERT INTO role_parents (role_name, parent_name) VALUES ($1, $2)`,
					r.Name, parent,
				)
				if err != nil {
					return fmt.Errorf("inserting parent %q for role %q: %w", parent, r.Name, err)
				}
			}
		}

		for _, p := range perms {
			id := p.ID
			if id == "" {
				id = uuid.New().String()
			}
			_, err := tx.Exec(ctx,
				`INSERT INTO permissions (id, role, resource, action) VALUES ($1, $2, $3, $4)`,
				id, p.Role, p.Resource, p.Action,
			)
			if err != nil {
				return fmt.Errorf("inserting permission for role %q: %w", p.Role, err)
			}
		}

		return nil
	})
}

func (s *Store) Sync(ctx context.Context, roles []*store.Role, perms []*store.Permission, assignments []store.ScopedAssignment) error {
	return pgutil.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		for _, table := range []string{"assignments", "permissions", "role_parents", "roles"} {
			if _, err := tx.Exec(ctx, fmt.Sprintf("DELETE FROM %s", table)); err != nil {
				return fmt.Errorf("clearing %s: %w", table, err)
			}
		}

		for _, r := range roles {
			createdAt := r.CreatedAt
			if createdAt.IsZero() {
				createdAt = time.Now()
			}
			_, err := tx.Exec(ctx,
				`INSERT INTO roles (name, description, created_at) VALUES ($1, $2, $3)`,
				r.Name, r.Description, createdAt,
			)
			if err != nil {
				return fmt.Errorf("inserting role %q: %w", r.Name, err)
			}
		}

		for _, r := range roles {
			for _, parent := range r.Parents {
				_, err := tx.Exec(ctx,
					`INSERT INTO role_parents (role_name, parent_name) VALUES ($1, $2)`,
					r.Name, parent,
				)
				if err != nil {
					return fmt.Errorf("inserting parent %q for role %q: %w", parent, r.Name, err)
				}
			}
		}

		for _, p := range perms {
			id := p.ID
			if id == "" {
				id = uuid.New().String()
			}
			_, err := tx.Exec(ctx,
				`INSERT INTO permissions (id, role, resource, action) VALUES ($1, $2, $3, $4)`,
				id, p.Role, p.Resource, p.Action,
			)
			if err != nil {
				return fmt.Errorf("inserting permission for role %q: %w", p.Role, err)
			}
		}

		for _, a := range assignments {
			_, err := tx.Exec(ctx,
				`INSERT INTO assignments (subject, role, scope_type, scope_id) VALUES ($1, $2, $3, $4)`,
				a.Subject, a.Role, a.ScopeType, a.ScopeID,
			)
			if err != nil {
				return fmt.Errorf("inserting assignment %q → %q (scope %s/%s): %w", a.Subject, a.Role, a.ScopeType, a.ScopeID, err)
			}
		}

		return nil
	})
}

// --- Helpers ---

func (s *Store) getRoleParents(ctx context.Context, roleName string) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT parent_name FROM role_parents WHERE role_name = $1 ORDER BY parent_name`, roleName,
	)
	if err != nil {
		return nil, fmt.Errorf("getting parents for role %q: %w", roleName, err)
	}
	defer rows.Close()

	var parents []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, fmt.Errorf("scanning parent: %w", err)
		}
		parents = append(parents, p)
	}
	return parents, rows.Err()
}

// getAllRoleParents fetches all parent relationships in a single query.
func (s *Store) getAllRoleParents(ctx context.Context) (map[string][]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT role_name, parent_name FROM role_parents ORDER BY role_name, parent_name`,
	)
	if err != nil {
		return nil, fmt.Errorf("getting all role parents: %w", err)
	}
	defer rows.Close()

	parents := make(map[string][]string)
	for rows.Next() {
		var roleName, parentName string
		if err := rows.Scan(&roleName, &parentName); err != nil {
			return nil, fmt.Errorf("scanning role parent: %w", err)
		}
		parents[roleName] = append(parents[roleName], parentName)
	}
	return parents, rows.Err()
}
