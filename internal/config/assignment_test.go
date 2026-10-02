package config

import (
	"errors"
	"testing"

	"github.com/ledatu/csar-authz/internal/engine"
)

func TestLoadFromBytes_RejectsInvalidAdminGrants(t *testing.T) {
	for _, yaml := range []string{
		"policy:\n  roles:\n    - {name: tenant_admin}\n    - {name: platform_admin}\nbootstrap_assignments:\n  - {subject: user, role: tenant_admin, scope_type: platform}",
		"policy:\n  roles:\n    - {name: tenant_admin}\n    - {name: platform_admin}\nbootstrap_assignments:\n  - {subject: user, role: platform_admin, scope_type: tenant, scope_id: 'wildberries:seller'}",
	} {
		if _, err := LoadFromBytes([]byte(yaml)); !errors.Is(err, engine.ErrInvalidAssignment) {
			t.Fatalf("expected admin assignment validation, got %v", err)
		}
	}
}
