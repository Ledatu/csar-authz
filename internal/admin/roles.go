package admin

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/ledatu/csar-authz/internal/store"
	"github.com/ledatu/csar-core/apierror"
)

type roleResponse struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Parents     []string `json:"parents"`
	CreatedAt   int64    `json:"created_at"`
}

func (h *Handler) handleListRoles(w http.ResponseWriter, r *http.Request) {
	subject := extractSubject(r)
	if subject == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
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

	roles, err := h.engine.ListRoles(r.Context())
	if err != nil {
		h.logger.Error("failed to list roles", "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to list roles").Write(w)
		return
	}

	resp := make([]roleResponse, len(roles))
	for i, role := range roles {
		resp[i] = roleResponse{
			Name:        role.Name,
			Description: role.Description,
			Parents:     role.Parents,
			CreatedAt:   role.CreatedAt.Unix(),
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

type createRoleRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Parents     []string `json:"parents"`
}

func (h *Handler) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	subject := extractSubject(r)
	if subject == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	var body createRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		apierror.New("bad_request", http.StatusBadRequest, "request body must contain name").Write(w)
		return
	}

	if apiErr := h.requirePermission(r, subject, "platform.roles.create", "platform", ""); apiErr != nil {
		writeError(w, apiErr)
		return
	}

	role := &store.Role{
		Name:        body.Name,
		Description: body.Description,
		Parents:     body.Parents,
	}
	if err := h.engine.CreateRole(r.Context(), role); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			apierror.New("already_exists", http.StatusConflict, "role already exists").Write(w)
			return
		}
		h.logger.Error("failed to create role", "name", body.Name, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to create role").Write(w)
		return
	}

	afterJSON, _ := json.Marshal(body)
	if err := h.recordAudit(r, subject, "role.create", "role", body.Name, "platform", "", afterJSON); err != nil {
		apierror.New("audit_error", http.StatusInternalServerError, "mutation succeeded but audit write failed").Write(w)
		return
	}

	writeJSON(w, http.StatusCreated, roleResponse{
		Name:        role.Name,
		Description: role.Description,
		Parents:     role.Parents,
		CreatedAt:   role.CreatedAt.Unix(),
	})
}

func (h *Handler) handleGetRole(w http.ResponseWriter, r *http.Request) {
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

	role, err := h.engine.GetRole(r.Context(), roleName)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			apierror.New("not_found", http.StatusNotFound, "role not found").Write(w)
			return
		}
		h.logger.Error("failed to get role", "name", roleName, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to get role").Write(w)
		return
	}

	writeJSON(w, http.StatusOK, roleResponse{
		Name:        role.Name,
		Description: role.Description,
		Parents:     role.Parents,
		CreatedAt:   role.CreatedAt.Unix(),
	})
}

func (h *Handler) handleDeleteRole(w http.ResponseWriter, r *http.Request) {
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

	if apiErr := h.requirePermission(r, subject, "platform.roles.delete", "platform", ""); apiErr != nil {
		writeError(w, apiErr)
		return
	}

	if err := h.engine.DeleteRole(r.Context(), roleName); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			apierror.New("not_found", http.StatusNotFound, "role not found").Write(w)
			return
		}
		h.logger.Error("failed to delete role", "name", roleName, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to delete role").Write(w)
		return
	}

	if err := h.recordAudit(r, subject, "role.delete", "role", roleName, "platform", "", nil); err != nil {
		apierror.New("audit_error", http.StatusInternalServerError, "mutation succeeded but audit write failed").Write(w)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
