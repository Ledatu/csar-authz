package server

import (
	"testing"

	pb "github.com/ledatu/csar-proto/csar/authz/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAssignRole_RejectsAdminScopeMismatch(t *testing.T) {
	srv, ctx := setupTestServer(t)
	for _, req := range []*pb.AssignRoleRequest{
		{Subject: "user", Role: "platform_admin", ScopeType: "tenant", ScopeId: "wildberries:seller"},
		{Subject: "user", Role: "tenant_admin", ScopeType: "platform"},
		{Subject: "user", Role: "tenant_admin", ScopeType: "tenant", ScopeId: "wildberries:*"},
	} {
		if _, err := srv.AssignRole(ctx, req); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("expected InvalidArgument for %v, got %v", req, err)
		}
	}
}
