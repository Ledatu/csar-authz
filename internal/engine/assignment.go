package engine

import (
	"errors"
	"fmt"
	"strings"
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
		if scopeType != ScopeTenant || !validAccountScope(scopeID) {
			return fmt.Errorf("%w: tenant_admin requires tenant scope with a literal marketplace:account scope_id", ErrInvalidAssignment)
		}
	}
	return nil
}

func validAccountScope(scopeID string) bool {
	marketplace, account, ok := strings.Cut(scopeID, ":")
	if !ok || marketplace == "" || account == "" {
		return false
	}
	for i, c := range marketplace {
		if (c >= 'a' && c <= 'z') || (i > 0 && ((c >= '0' && c <= '9') || c == '_' || c == '-')) {
			continue
		}
		return false
	}
	for i, c := range account {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			(i > 0 && (c == '-' || c == '_' || c == '.')) {
			continue
		}
		return false
	}
	return true
}
