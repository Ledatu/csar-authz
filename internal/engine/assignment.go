package engine

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ledatu/csar-core/authntokens"
)

// ErrInvalidAssignment identifies an admin role assigned outside its scope.
var ErrInvalidAssignment = errors.New("invalid role assignment")

// ValidateRoleAssignment constrains direct grants of built-in admin roles.
// Inheritance remains valid: a platform_admin inherits tenant capabilities.
// Existing legacy assignments are not rewritten; they can still be revoked.
func ValidateRoleAssignment(role, scopeType, scopeID string) error {
	switch role {
	case "platform_admin":
		if scopeType != ScopePlatform || scopeID != "" {
			return fmt.Errorf("%w: platform_admin requires platform scope with an empty scope_id", ErrInvalidAssignment)
		}
	case "tenant_admin":
		if scopeType != ScopeTenant || !validTenantAdminScope(scopeID) {
			return fmt.Errorf("%w: tenant_admin requires tenant scope with a bounded literal scope_id", ErrInvalidAssignment)
		}
	}
	return nil
}

func validTenantAdminScope(scopeID string) bool {
	if (authntokens.ScopeRef{Type: ScopeTenant, ID: scopeID}).Validate() != nil || strings.ContainsAny(scopeID, "/@") {
		return false
	}
	// Protect the control plane from empty/ambiguous segments without assigning
	// application meaning to their count or interpreting a marketplace account.
	for _, segment := range strings.Split(scopeID, ":") {
		if segment == "" || strings.ContainsAny(segment[:1], "._-") {
			return false
		}
	}
	return true
}
