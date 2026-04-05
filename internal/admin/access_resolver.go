package admin

import (
	"context"

	"github.com/ledatu/csar-authz/internal/engine"
	"github.com/ledatu/csar-authz/internal/store"
)

type scopeKey struct {
	scopeType string
	scopeID   string
}

type resolvedAdminAccess struct {
	platformAdmin        bool
	platformCapabilities []string
	tenantCapabilities   map[string][]string
	directTenants        []string
}

// resolveAdminAccess batches assignment, role, and permission reads for the
// admin browser surface. CheckAccess remains a separate hot path and is not
// rewritten in this change.
func (h *Handler) resolveAdminAccess(ctx context.Context, subject string) (*resolvedAdminAccess, error) {
	assignments, err := h.engine.ListSubjectAssignments(ctx, subject)
	if err != nil {
		return nil, err
	}
	if len(assignments) == 0 {
		return &resolvedAdminAccess{
			tenantCapabilities: make(map[string][]string),
		}, nil
	}

	scopeRoles := make(map[scopeKey][]string)
	scopeOrder := make([]scopeKey, 0)
	seenScopes := make(map[scopeKey]struct{})
	seenTenants := make(map[string]struct{})
	directTenants := make([]string, 0)
	directRoleNames := make([]string, 0)
	seenDirectRoles := make(map[string]struct{})

	for _, assignment := range assignments {
		key := scopeKey{scopeType: assignment.ScopeType, scopeID: assignment.ScopeID}
		if _, ok := seenScopes[key]; !ok {
			seenScopes[key] = struct{}{}
			scopeOrder = append(scopeOrder, key)
		}
		scopeRoles[key] = append(scopeRoles[key], assignment.Role)
		if _, ok := seenDirectRoles[assignment.Role]; !ok {
			seenDirectRoles[assignment.Role] = struct{}{}
			directRoleNames = append(directRoleNames, assignment.Role)
		}

		if assignment.ScopeType == "tenant" && assignment.ScopeID != "" {
			if _, ok := seenTenants[assignment.ScopeID]; !ok {
				seenTenants[assignment.ScopeID] = struct{}{}
				directTenants = append(directTenants, assignment.ScopeID)
			}
		}
	}

	closureByRole, err := h.engine.ListRoleClosure(ctx, directRoleNames)
	if err != nil {
		return nil, err
	}
	effectiveRolesByScope := make(map[scopeKey][]string, len(scopeOrder))
	roleSet := make(map[string]struct{})
	roleNames := make([]string, 0)

	for _, key := range scopeOrder {
		effective := mergeRoleClosure(scopeRoles[key], closureByRole)
		effectiveRolesByScope[key] = effective
		for _, roleName := range effective {
			if _, ok := roleSet[roleName]; ok {
				continue
			}
			roleSet[roleName] = struct{}{}
			roleNames = append(roleNames, roleName)
		}
	}

	permissionsByRole, err := h.engine.ListPermissionsForRoles(ctx, roleNames)
	if err != nil {
		return nil, err
	}

	resolved := &resolvedAdminAccess{
		tenantCapabilities: make(map[string][]string),
		directTenants:      directTenants,
	}

	for _, key := range scopeOrder {
		capabilities := collectAdminCapabilities(key.scopeType, effectiveRolesByScope[key], permissionsByRole)
		if len(capabilities) == 0 {
			continue
		}
		switch key.scopeType {
		case "platform":
			resolved.platformCapabilities = capabilities
		case "tenant":
			if key.scopeID != "" {
				resolved.tenantCapabilities[key.scopeID] = capabilities
			}
		}
	}

	resolved.platformAdmin = len(resolved.platformCapabilities) > 0
	return resolved, nil
}

func collectAdminCapabilities(scopeType string, effectiveRoles []string, permissionsByRole map[string][]*store.Permission) []string {
	seen := make(map[string]struct{})
	capabilities := make([]string, 0)

	for _, roleName := range effectiveRoles {
		for _, permission := range permissionsByRole[roleName] {
			if !engine.MatchResource(permission.Resource, "admin") {
				continue
			}
			for _, action := range expandAdminActions(scopeType, permission.Action) {
				if _, ok := seen[action]; ok {
					continue
				}
				seen[action] = struct{}{}
				capabilities = append(capabilities, action)
			}
		}
	}

	return capabilities
}

func mergeRoleClosure(directRoles []string, closureByRole map[string][]string) []string {
	seen := make(map[string]struct{}, len(directRoles))
	expanded := make([]string, 0, len(directRoles))

	for _, roleName := range directRoles {
		for _, effectiveRole := range closureByRole[roleName] {
			if _, ok := seen[effectiveRole]; ok {
				continue
			}
			seen[effectiveRole] = struct{}{}
			expanded = append(expanded, effectiveRole)
		}
	}

	return expanded
}
