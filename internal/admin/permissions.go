package admin

import (
	"encoding/json"
	"net/http"

	"github.com/ledatu/csar-authz/internal/store"
	"github.com/ledatu/csar-core/apierror"
)

type addPermissionRequest struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

type permissionResponse struct {
	ID       string `json:"id"`
	Role     string `json:"role"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

func (h *Handler) handleListRolePermissions(w http.ResponseWriter, r *http.Request) {
	subject := extractSubject(r)
	if subject == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	roleName := r.PathValue("role")
	if roleName == "" {
		apierror.New("bad_request", http.StatusBadRequest, "role name is required").Write(w)
		return
	}

	hasPlatform := h.requirePermission(r, subject, "platform.roles.read", "platform", "") == nil
	hasTenant := false
	if tenantID := r.URL.Query().Get("tenant_id"); tenantID != "" {
		hasTenant = h.requirePermission(r, subject, "tenant.roles.read", "tenant", tenantID) == nil
	}
	if !hasPlatform && !hasTenant {
		apierror.New(apierror.CodeAccessDenied, http.StatusForbidden, "insufficient permissions").Write(w)
		return
	}

	perms, err := h.engine.ListRolePermissions(r.Context(), roleName)
	if err != nil {
		h.logger.Error("failed to list role permissions", "role", roleName, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to list permissions").Write(w)
		return
	}

	resp := make([]permissionResponse, len(perms))
	for i, p := range perms {
		resp[i] = permissionResponse{ID: p.ID, Role: p.Role, Resource: p.Resource, Action: p.Action}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) handleAddPermission(w http.ResponseWriter, r *http.Request) {
	subject := extractSubject(r)
	if subject == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	roleName := r.PathValue("role")
	if roleName == "" {
		apierror.New("bad_request", http.StatusBadRequest, "role name is required").Write(w)
		return
	}

	var body addPermissionRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Resource == "" || body.Action == "" {
		apierror.New("bad_request", http.StatusBadRequest, "request body must contain resource and action").Write(w)
		return
	}

	if apiErr := h.requirePermission(r, subject, "platform.roles.create", "platform", ""); apiErr != nil {
		writeError(w, apiErr)
		return
	}

	perm := &store.Permission{
		Role:     roleName,
		Resource: body.Resource,
		Action:   body.Action,
	}
	if err := h.engine.AddPermission(r.Context(), perm); err != nil {
		h.logger.Error("failed to add permission", "role", roleName, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to add permission").Write(w)
		return
	}

	afterJSON, _ := json.Marshal(body)
	if err := h.recordAudit(r, subject, "permission.add", "permission", perm.ID, "platform", "", afterJSON); err != nil {
		apierror.New("audit_error", http.StatusInternalServerError, "mutation succeeded but audit write failed").Write(w)
		return
	}

	writeJSON(w, http.StatusCreated, permissionResponse{
		ID:       perm.ID,
		Role:     perm.Role,
		Resource: perm.Resource,
		Action:   perm.Action,
	})
}

func (h *Handler) handleRemovePermission(w http.ResponseWriter, r *http.Request) {
	subject := extractSubject(r)
	if subject == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	permID := r.PathValue("permId")
	if permID == "" {
		apierror.New("bad_request", http.StatusBadRequest, "permission ID is required").Write(w)
		return
	}

	if apiErr := h.requirePermission(r, subject, "platform.roles.delete", "platform", ""); apiErr != nil {
		writeError(w, apiErr)
		return
	}

	if err := h.engine.RemovePermission(r.Context(), permID); err != nil {
		h.logger.Error("failed to remove permission", "id", permID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to remove permission").Write(w)
		return
	}

	if err := h.recordAudit(r, subject, "permission.remove", "permission", permID, "platform", "", nil); err != nil {
		apierror.New("audit_error", http.StatusInternalServerError, "mutation succeeded but audit write failed").Write(w)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
