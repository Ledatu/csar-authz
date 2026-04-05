package admin

import "net/http"

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
	resolved, err := h.resolveAdminAccess(ctx, subject)
	if err != nil {
		h.logger.Error("failed to resolve capabilities", "subject", subject, "error", err)
		http.Error(w, "failed to fetch capabilities", http.StatusInternalServerError)
		return
	}

	resp := capabilitiesResponse{
		Subject:              subject,
		PlatformAdmin:        resolved.platformAdmin,
		PlatformCapabilities: resolved.platformCapabilities,
		TenantCapabilities:   resolved.tenantCapabilities,
	}

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
	resolved, err := h.resolveAdminAccess(ctx, subject)
	if err != nil {
		h.logger.Error("failed to resolve tenant access", "subject", subject, "error", err)
		http.Error(w, "failed to fetch tenants", http.StatusInternalServerError)
		return
	}

	if resolved.platformAdmin {
		tenants, err := h.engine.ListTenants(ctx)
		if err != nil {
			h.logger.Error("failed to list all tenants", "subject", subject, "error", err)
			http.Error(w, "failed to fetch tenants", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, myTenantsResponse{Subject: subject, Tenants: tenants})
		return
	}

	writeJSON(w, http.StatusOK, myTenantsResponse{Subject: subject, Tenants: resolved.directTenants})
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
