// Package grpcauthz provides a gRPC unary interceptor that enforces
// per-RPC authorization on the AuthzService. It runs after the JWT
// interceptor and checks whether the authenticated subject has the
// required admin permission for the requested method.
//
// CheckAccess is the only RPC exempt from authorization — it is the
// hot-path decision endpoint called by the router on every request.
//
// Any new RPCs added to the AuthzService proto MUST be registered in
// buildPolicies or they will be implicitly open.
package grpcauthz

import (
	"context"
	"sync/atomic"

	"github.com/ledatu/csar-authz/internal/engine"
	"github.com/ledatu/csar-core/authzconfig"
	"github.com/ledatu/csar-core/grpcjwt"
	pb "github.com/ledatu/csar-proto/csar/authz/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const servicePath = "/csar.authz.v1.AuthzService/"

const methodAssignRole = servicePath + "AssignRole"

// policyFunc extracts the required permission and scope from a request.
type policyFunc func(req any) (permission, scopeType, scopeID string)

// Interceptor enforces admin authorization on AuthzService RPCs.
type Interceptor struct {
	engine       *engine.Engine
	cfg          atomic.Pointer[authzconfig.AdminConfig]
	authnEnabled bool
	policies     map[string]policyFunc
}

// NewInterceptor creates an authorization interceptor.
// When authnEnabled is false (dev mode), RPCs pass through when no
// subject is present in the context.
func NewInterceptor(eng *engine.Engine, cfg *authzconfig.AdminConfig, authnEnabled bool) *Interceptor {
	i := &Interceptor{
		engine:       eng,
		authnEnabled: authnEnabled,
	}
	i.cfg.Store(cfg)
	i.policies = buildPolicies()
	return i
}

// SetConfig atomically replaces the admin configuration (for hot-reload).
func (i *Interceptor) SetConfig(cfg *authzconfig.AdminConfig) {
	i.cfg.Store(cfg)
}

// UnaryInterceptor returns the gRPC unary server interceptor.
func (i *Interceptor) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		policy, ok := i.policies[info.FullMethod]
		if !ok {
			return handler(ctx, req)
		}

		subject, hasSub := grpcjwt.SubjectFromContext(ctx)
		if !hasSub {
			if !i.authnEnabled {
				return handler(ctx, req)
			}
			return nil, status.Error(codes.Unauthenticated, "authentication required")
		}

		permission, scopeType, scopeID := policy(req)

		result, err := i.engine.CheckAccess(ctx, subject, scopeType, scopeID, "admin", permission)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "authorization check failed: %v", err)
		}
		if !result.Allowed {
			return nil, status.Error(codes.PermissionDenied, "insufficient permissions")
		}

		if info.FullMethod == methodAssignRole && scopeType == "tenant" {
			if err := i.enforceDelegation(ctx, subject, req); err != nil {
				return nil, err
			}
		}

		return handler(ctx, req)
	}
}

// enforceDelegation mirrors admin.Handler.enforceDelegation: platform
// admins may assign any role; tenant admins are restricted to the
// configured delegatable_roles list.
func (i *Interceptor) enforceDelegation(ctx context.Context, subject string, req any) error {
	r, ok := req.(*pb.AssignRoleRequest)
	if !ok {
		return nil
	}

	cfg := i.cfg.Load()

	result, err := i.engine.CheckAccess(ctx, subject, "platform", "", "admin", "platform.roles.assign")
	if err == nil && result.Allowed {
		return nil
	}

	if len(cfg.DelegatableRoles) > 0 {
		for _, dr := range cfg.DelegatableRoles {
			if dr == r.Role {
				return nil
			}
		}
		return status.Error(codes.PermissionDenied, "role is not delegatable by tenant admins")
	}

	return nil
}

func buildPolicies() map[string]policyFunc {
	m := make(map[string]policyFunc, 12)

	static := func(permission string) policyFunc {
		return func(_ any) (string, string, string) {
			return permission, "platform", ""
		}
	}

	m[servicePath+"CreateRole"] = static("platform.roles.create")
	m[servicePath+"DeleteRole"] = static("platform.roles.delete")
	m[servicePath+"GetRole"] = static("platform.roles.read")
	m[servicePath+"ListRoles"] = static("platform.roles.read")
	m[servicePath+"AddPermission"] = static("platform.roles.create")
	m[servicePath+"RemovePermission"] = static("platform.roles.delete")
	m[servicePath+"ListRolePermissions"] = static("platform.roles.read")
	m[servicePath+"ListSubjectScopes"] = static("platform.roles.read")

	m[servicePath+"AssignRole"] = func(req any) (string, string, string) {
		r := req.(*pb.AssignRoleRequest)
		if r.ScopeType == "tenant" {
			return "tenant.members.assign_role", r.ScopeType, r.ScopeId
		}
		return "platform.roles.assign", r.ScopeType, r.ScopeId
	}

	m[servicePath+"RevokeRole"] = func(req any) (string, string, string) {
		r := req.(*pb.RevokeRoleRequest)
		if r.ScopeType == "tenant" {
			return "tenant.members.revoke_role", r.ScopeType, r.ScopeId
		}
		return "platform.roles.revoke", r.ScopeType, r.ScopeId
	}

	m[servicePath+"ListSubjectRoles"] = func(req any) (string, string, string) {
		r := req.(*pb.ListSubjectRolesRequest)
		if r.ScopeType == "tenant" {
			return "tenant.members.read", r.ScopeType, r.ScopeId
		}
		return "platform.roles.read", r.ScopeType, r.ScopeId
	}

	m[servicePath+"ListScopeAssignments"] = func(req any) (string, string, string) {
		r := req.(*pb.ListScopeAssignmentsRequest)
		return "tenant.members.read", r.ScopeType, r.ScopeId
	}

	return m
}
