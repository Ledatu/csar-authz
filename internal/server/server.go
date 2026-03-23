// Package server implements the AuthzService gRPC server.
package server

import (
	"context"
	"errors"

	"github.com/ledatu/csar-authz/internal/engine"
	"github.com/ledatu/csar-authz/internal/store"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/grpcjwt"
	pb "github.com/ledatu/csar-proto/csar/authz/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server implements the AuthzServiceServer gRPC interface.
type Server struct {
	pb.UnimplementedAuthzServiceServer
	engine *engine.Engine
}

// New creates a new gRPC server backed by the given engine.
func New(e *engine.Engine) *Server {
	return &Server{engine: e}
}

// ─── Access Check ───────────────────────────────────────────────────────────

// CheckAccess evaluates whether a subject can perform an action on a resource.
// If Subject is empty in the request, it falls back to the JWT-extracted
// subject from the context (set by the authn interceptor).
func (s *Server) CheckAccess(ctx context.Context, req *pb.CheckAccessRequest) (*pb.CheckAccessResponse, error) {
	if req.Subject == "" {
		if sub, ok := grpcjwt.SubjectFromContext(ctx); ok {
			req.Subject = sub
		}
	}
	if req.Subject == "" {
		return nil, status.Error(codes.InvalidArgument, "subject is required")
	}
	if req.Resource == "" {
		return nil, status.Error(codes.InvalidArgument, "resource is required")
	}
	if req.Action == "" {
		return nil, status.Error(codes.InvalidArgument, "action is required")
	}
	if err := validateScope(req.ScopeType, req.ScopeId); err != nil {
		return nil, err
	}

	result, err := s.engine.CheckAccess(ctx, req.Subject, req.ScopeType, req.ScopeId, req.Resource, req.Action)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "authorization check failed: %v", err)
	}

	headers := engine.EnrichedHeaders(result)
	// Let backends identify the subject without
	// re-parsing router auth headers — the router merges these onto the upstream request.
	if req.Subject != "" {
		headers[gatewayctx.HeaderSubject] = req.Subject
	}
	if result.Allowed {
		headers[gatewayctx.HeaderAuthzResult] = "allow"
	} else {
		headers[gatewayctx.HeaderAuthzResult] = "deny"
	}

	return &pb.CheckAccessResponse{
		Allowed:         result.Allowed,
		MatchedRoles:    result.MatchedRoles,
		EnrichedHeaders: headers,
	}, nil
}

// ─── Role Management ────────────────────────────────────────────────────────

// CreateRole creates a new role.
func (s *Server) CreateRole(ctx context.Context, req *pb.CreateRoleRequest) (*pb.CreateRoleResponse, error) {
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	role := &store.Role{
		Name:        req.Name,
		Description: req.Description,
		Parents:     req.Parents,
	}

	if err := s.engine.CreateRole(ctx, role); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			return nil, status.Errorf(codes.AlreadyExists, "role %q already exists", req.Name)
		}
		if errors.Is(err, store.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "parent role: %v", err)
		}
		return nil, status.Errorf(codes.Internal, "creating role: %v", err)
	}

	return &pb.CreateRoleResponse{
		Role: roleToProto(role),
	}, nil
}

// DeleteRole removes a role.
func (s *Server) DeleteRole(ctx context.Context, req *pb.DeleteRoleRequest) (*pb.DeleteRoleResponse, error) {
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	if err := s.engine.DeleteRole(ctx, req.Name); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "role %q not found", req.Name)
		}
		return nil, status.Errorf(codes.Internal, "deleting role: %v", err)
	}

	return &pb.DeleteRoleResponse{}, nil
}

// GetRole returns a single role.
func (s *Server) GetRole(ctx context.Context, req *pb.GetRoleRequest) (*pb.GetRoleResponse, error) {
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	role, err := s.engine.GetRole(ctx, req.Name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "role %q not found", req.Name)
		}
		return nil, status.Errorf(codes.Internal, "getting role: %v", err)
	}

	return &pb.GetRoleResponse{
		Role: roleToProto(role),
	}, nil
}

// ListRoles returns all defined roles.
func (s *Server) ListRoles(ctx context.Context, _ *pb.ListRolesRequest) (*pb.ListRolesResponse, error) {
	roles, err := s.engine.ListRoles(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "listing roles: %v", err)
	}

	pbRoles := make([]*pb.Role, len(roles))
	for i, r := range roles {
		pbRoles[i] = roleToProto(r)
	}

	return &pb.ListRolesResponse{Roles: pbRoles}, nil
}

// ─── Subject-Role Assignment ────────────────────────────────────────────────

// AssignRole grants a role to a subject within a scope.
func (s *Server) AssignRole(ctx context.Context, req *pb.AssignRoleRequest) (*pb.AssignRoleResponse, error) {
	if req.Subject == "" {
		return nil, status.Error(codes.InvalidArgument, "subject is required")
	}
	if req.Role == "" {
		return nil, status.Error(codes.InvalidArgument, "role is required")
	}
	if err := validateScope(req.ScopeType, req.ScopeId); err != nil {
		return nil, err
	}

	if err := s.engine.AssignRole(ctx, req.Subject, req.Role, req.ScopeType, req.ScopeId); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "role %q not found", req.Role)
		}
		return nil, status.Errorf(codes.Internal, "assigning role: %v", err)
	}

	return &pb.AssignRoleResponse{}, nil
}

// RevokeRole removes a role from a subject within a scope.
func (s *Server) RevokeRole(ctx context.Context, req *pb.RevokeRoleRequest) (*pb.RevokeRoleResponse, error) {
	if req.Subject == "" {
		return nil, status.Error(codes.InvalidArgument, "subject is required")
	}
	if req.Role == "" {
		return nil, status.Error(codes.InvalidArgument, "role is required")
	}
	if err := validateScope(req.ScopeType, req.ScopeId); err != nil {
		return nil, err
	}

	if err := s.engine.RevokeRole(ctx, req.Subject, req.Role, req.ScopeType, req.ScopeId); err != nil {
		return nil, status.Errorf(codes.Internal, "revoking role: %v", err)
	}

	return &pb.RevokeRoleResponse{}, nil
}

// ListSubjectRoles returns all roles assigned to a subject within a scope.
func (s *Server) ListSubjectRoles(ctx context.Context, req *pb.ListSubjectRolesRequest) (*pb.ListSubjectRolesResponse, error) {
	if req.Subject == "" {
		return nil, status.Error(codes.InvalidArgument, "subject is required")
	}
	if err := validateScope(req.ScopeType, req.ScopeId); err != nil {
		return nil, err
	}

	roles, err := s.engine.ListSubjectRoles(ctx, req.Subject, req.ScopeType, req.ScopeId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "listing subject roles: %v", err)
	}

	return &pb.ListSubjectRolesResponse{Roles: roles}, nil
}

// ─── Permission Management ──────────────────────────────────────────────────

// AddPermission adds a permission to a role.
func (s *Server) AddPermission(ctx context.Context, req *pb.AddPermissionRequest) (*pb.AddPermissionResponse, error) {
	if req.Role == "" {
		return nil, status.Error(codes.InvalidArgument, "role is required")
	}
	if req.Resource == "" {
		return nil, status.Error(codes.InvalidArgument, "resource is required")
	}
	if req.Action == "" {
		return nil, status.Error(codes.InvalidArgument, "action is required")
	}

	perm := &store.Permission{
		Role:     req.Role,
		Resource: req.Resource,
		Action:   req.Action,
	}

	if err := s.engine.AddPermission(ctx, perm); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "role %q not found", req.Role)
		}
		return nil, status.Errorf(codes.Internal, "adding permission: %v", err)
	}

	return &pb.AddPermissionResponse{
		Permission: permToProto(perm),
	}, nil
}

// RemovePermission removes a permission by ID.
func (s *Server) RemovePermission(ctx context.Context, req *pb.RemovePermissionRequest) (*pb.RemovePermissionResponse, error) {
	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}

	if err := s.engine.RemovePermission(ctx, req.Id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "permission %q not found", req.Id)
		}
		return nil, status.Errorf(codes.Internal, "removing permission: %v", err)
	}

	return &pb.RemovePermissionResponse{}, nil
}

// ListRolePermissions returns all permissions for a role.
func (s *Server) ListRolePermissions(ctx context.Context, req *pb.ListRolePermissionsRequest) (*pb.ListRolePermissionsResponse, error) {
	if req.Role == "" {
		return nil, status.Error(codes.InvalidArgument, "role is required")
	}

	perms, err := s.engine.ListRolePermissions(ctx, req.Role)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "listing permissions: %v", err)
	}

	pbPerms := make([]*pb.Permission, len(perms))
	for i, p := range perms {
		pbPerms[i] = permToProto(p)
	}

	return &pb.ListRolePermissionsResponse{Permissions: pbPerms}, nil
}

// ─── Subject Reassignment ───────────────────────────────────────────────────

// ReassignSubject moves all assignments from one subject to another.
func (s *Server) ReassignSubject(ctx context.Context, req *pb.ReassignSubjectRequest) (*pb.ReassignSubjectResponse, error) {
	if req.SourceSubject == "" {
		return nil, status.Error(codes.InvalidArgument, "source_subject is required")
	}
	if req.TargetSubject == "" {
		return nil, status.Error(codes.InvalidArgument, "target_subject is required")
	}
	if req.SourceSubject == req.TargetSubject {
		return nil, status.Error(codes.InvalidArgument, "source and target must differ")
	}

	count, err := s.engine.ReassignSubject(ctx, req.SourceSubject, req.TargetSubject)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "reassigning subject: %v", err)
	}

	return &pb.ReassignSubjectResponse{Reassigned: int32(count)}, nil
}

// ─── Scope Queries ──────────────────────────────────────────────────────────

// ListScopeAssignments returns all assignments within a scope (e.g., all members of a tenant).
func (s *Server) ListScopeAssignments(ctx context.Context, req *pb.ListScopeAssignmentsRequest) (*pb.ListScopeAssignmentsResponse, error) {
	if err := validateScope(req.ScopeType, req.ScopeId); err != nil {
		return nil, err
	}

	assignments, err := s.engine.ListScopeAssignments(ctx, req.ScopeType, req.ScopeId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "listing scope assignments: %v", err)
	}

	pbAssignments := make([]*pb.ScopeAssignment, len(assignments))
	for i, a := range assignments {
		pbAssignments[i] = &pb.ScopeAssignment{
			Subject:   a.Subject,
			Role:      a.Role,
			ScopeType: a.ScopeType,
			ScopeId:   a.ScopeID,
		}
	}

	return &pb.ListScopeAssignmentsResponse{Assignments: pbAssignments}, nil
}

// ListSubjectScopes returns all scopes where a subject has assignments.
func (s *Server) ListSubjectScopes(ctx context.Context, req *pb.ListSubjectScopesRequest) (*pb.ListSubjectScopesResponse, error) {
	if req.Subject == "" {
		return nil, status.Error(codes.InvalidArgument, "subject is required")
	}

	scopes, err := s.engine.ListSubjectScopes(ctx, req.Subject)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "listing subject scopes: %v", err)
	}

	pbScopes := make([]*pb.SubjectScope, len(scopes))
	for i, sc := range scopes {
		pbScopes[i] = &pb.SubjectScope{
			ScopeType: sc.ScopeType,
			ScopeId:   sc.ScopeID,
		}
	}

	return &pb.ListSubjectScopesResponse{Scopes: pbScopes}, nil
}

// ─── Scope Helpers ──────────────────────────────────────────────────────────

var validScopeTypes = map[string]struct{}{
	"platform": {},
	"tenant":   {},
}

// validateScope returns an error if scope_type is missing or unrecognized,
// or if scope_type=tenant but scope_id is empty.
func validateScope(scopeType, scopeID string) error {
	if scopeType == "" {
		return status.Error(codes.InvalidArgument, "scope_type is required")
	}
	if _, ok := validScopeTypes[scopeType]; !ok {
		return status.Errorf(codes.InvalidArgument, "scope_type must be \"platform\" or \"tenant\", got %q", scopeType)
	}
	if scopeType == "tenant" && scopeID == "" {
		return status.Error(codes.InvalidArgument, "scope_id is required when scope_type is \"tenant\"")
	}
	return nil
}

// ─── Proto Conversion Helpers ───────────────────────────────────────────────

func roleToProto(r *store.Role) *pb.Role {
	return &pb.Role{
		Name:        r.Name,
		Description: r.Description,
		Parents:     r.Parents,
		CreatedAt:   r.CreatedAt.Unix(),
	}
}

func permToProto(p *store.Permission) *pb.Permission {
	return &pb.Permission{
		Id:       p.ID,
		Role:     p.Role,
		Resource: p.Resource,
		Action:   p.Action,
	}
}
