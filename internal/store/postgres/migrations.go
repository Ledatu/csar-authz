package postgres

import "github.com/ledatu/csar-core/pgutil"

var migrations = []pgutil.Migration{
	{
		Name: "001_initial",
		Up: `
CREATE TABLE IF NOT EXISTS roles (
    name        TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS role_parents (
    role_name   TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
    parent_name TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
    PRIMARY KEY (role_name, parent_name)
);

CREATE TABLE IF NOT EXISTS permissions (
    id         TEXT PRIMARY KEY,
    role       TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
    resource   TEXT NOT NULL,
    action     TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_permissions_role ON permissions(role);

CREATE TABLE IF NOT EXISTS assignments (
    subject     TEXT NOT NULL,
    role        TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (subject, role)
);

CREATE INDEX IF NOT EXISTS idx_assignments_subject ON assignments(subject);
`,
	},
	{
		Name: "002_scoped_assignments",
		Up: `
ALTER TABLE assignments ADD COLUMN scope_type TEXT NOT NULL DEFAULT 'platform';
ALTER TABLE assignments ADD COLUMN scope_id TEXT NOT NULL DEFAULT '';

ALTER TABLE assignments DROP CONSTRAINT assignments_pkey;
ALTER TABLE assignments ADD PRIMARY KEY (subject, scope_type, scope_id, role);

CREATE INDEX IF NOT EXISTS idx_assignments_subject_scope
    ON assignments(subject, scope_type, scope_id);
CREATE INDEX IF NOT EXISTS idx_assignments_scope
    ON assignments(scope_type, scope_id);
`,
	},
}
