package admin

import (
	"context"
	"net/http"

	"github.com/ledatu/csar-authz/internal/engine"
)

var platformCapabilities = []string{
	"platform.roles.read",
	"platform.roles.create",
	"platform.roles.delete",
	"platform.roles.assign",
	"platform.roles.revoke",
	"admin.audit.read",
}

var tenantCapabilities = []string{
	"tenant.roles.read",
	"tenant.members.read",
	"tenant.members.assign_role",
	"tenant.members.revoke_role",
}

type capabilitiesResponse struct {
	Subject              string              `json:"subject"`
	PlatformAdmin        bool                `json:"platform_admin"`
	PlatformCapabilities []string            `json:"platform_capabilities"`
	TenantCapabilities   map[string][]string `json:"tenant_capabilities"`
}

func (h *Handler) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	subject := extractSubject(r)
	if subject == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	ctx := r.Context()

	scopes, err := h.engine.ListSubjectScopes(ctx, subject)
	if err != nil {
		h.logger.Error("failed to list subject scopes", "subject", subject, "error", err)
		http.Error(w, "failed to fetch scopes", http.StatusInternalServerError)
		return
	}

	resp := capabilitiesResponse{
		Subject:            subject,
		TenantCapabilities: make(map[string][]string),
	}

	for _, scope := range scopes {
		perms := h.collectAdminPermissions(ctx, subject, scope.ScopeType, scope.ScopeID)
		if len(perms) == 0 {
			continue
		}
		if scope.ScopeType == "platform" {
			resp.PlatformCapabilities = perms
		} else if scope.ScopeType == "tenant" && scope.ScopeID != "" {
			resp.TenantCapabilities[scope.ScopeID] = perms
		}
	}

	resp.PlatformAdmin = len(resp.PlatformCapabilities) > 0

	writeJSON(w, http.StatusOK, resp)
}

type myTenantsResponse struct {
	Subject string   `json:"subject"`
	Tenants []string `json:"tenants"`
}

func (h *Handler) handleMyTenants(w http.ResponseWriter, r *http.Request) {
	subject := extractSubject(r)
	if subject == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	ctx := r.Context()

	isPlatformAdmin := len(h.collectAdminPermissions(ctx, subject, "platform", "")) > 0
	if isPlatformAdmin {
		tenants, err := h.engine.ListTenants(ctx)
		if err != nil {
			h.logger.Error("failed to list all tenants", "subject", subject, "error", err)
			http.Error(w, "failed to fetch tenants", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, myTenantsResponse{Subject: subject, Tenants: tenants})
		return
	}

	scopes, err := h.engine.ListSubjectScopes(ctx, subject)
	if err != nil {
		h.logger.Error("failed to list subject scopes", "subject", subject, "error", err)
		http.Error(w, "failed to fetch tenants", http.StatusInternalServerError)
		return
	}

	var tenants []string
	for _, scope := range scopes {
		if scope.ScopeType == "tenant" && scope.ScopeID != "" {
			tenants = append(tenants, scope.ScopeID)
		}
	}

	writeJSON(w, http.StatusOK, myTenantsResponse{Subject: subject, Tenants: tenants})
}

// collectAdminPermissions resolves all admin-resource permissions for a subject in a scope.
func (h *Handler) collectAdminPermissions(ctx context.Context, subject, scopeType, scopeID string) []string {
	roles, err := h.engine.ListSubjectRoles(ctx, subject, scopeType, scopeID)
	if err != nil {
		h.logger.Warn("failed to list roles for capabilities", "subject", subject, "error", err)
		return nil
	}

	effectiveRoles, err := h.engine.ExpandRoles(ctx, roles)
	if err != nil {
		h.logger.Warn("failed to expand roles", "subject", subject, "error", err)
		return nil
	}

	seen := make(map[string]struct{})
	var perms []string
	for _, roleName := range effectiveRoles {
		rolePerms, err := h.engine.ListRolePermissions(ctx, roleName)
		if err != nil {
			continue
		}
		for _, p := range rolePerms {
			if !engine.MatchResource(p.Resource, "admin") {
				continue
			}
			for _, action := range expandAdminActions(scopeType, p.Action) {
				if _, dup := seen[action]; dup {
					continue
				}
				seen[action] = struct{}{}
				perms = append(perms, action)
			}
		}
	}
	return perms
}

func expandAdminActions(scopeType, action string) []string {
	if action != "*" {
		return []string{action}
	}

	switch scopeType {
	case "platform":
		return platformCapabilities
	case "tenant":
		return tenantCapabilities
	default:
		return []string{action}
	}
}
