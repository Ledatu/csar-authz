package postgres

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ledatu/csar-authz/internal/store"
	"github.com/ledatu/csar-core/audit"
	"github.com/ledatu/csar-core/gatewayctx"
)

// This fixture never uses CSAR_TEST_DSN; existing application databases are forbidden.
func auditFixture(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("AUDIT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated localhost audit database not configured")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if (cfg.ConnConfig.Host != "127.0.0.1" && cfg.ConnConfig.Host != "localhost") || cfg.ConnConfig.Database != "csar_audit_test" || len(cfg.ConnConfig.Fallbacks) > 0 {
		t.Fatal("only isolated localhost csar_audit_test accepted")
	}
	ctx := context.Background()
	admin, err := pgxpool.NewWithConfig(ctx, cfg.Copy())
	if err != nil {
		t.Fatal(err)
	}
	schema := "producer_test_" + uuid.NewString()[:8]
	ident := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+ident); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = ident
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, err := admin.Exec(ctx, "DROP SCHEMA "+ident+" CASCADE")
		admin.Close()
		if err != nil {
			t.Error(err)
		}
	})
	s := &Store{pool: pool, logger: slog.Default()}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnableAuditOutbox(ctx); err != nil {
		t.Fatal(err)
	}
	return s
}
func actorContext() context.Context {
	return gatewayctx.NewContext(context.Background(), &gatewayctx.Identity{Subject: "verified-user", RequestID: "test-request"})
}

func TestAuthzOutboxAtomicMutations(t *testing.T) {
	s := auditFixture(t)
	ctx := actorContext()
	if err := s.CreateRole(ctx, &store.Role{Name: "test-role"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AssignRole(ctx, "target-user", "test-role", "tenant", "wildberries:seller"); err != nil {
		t.Fatal(err)
	}
	perm := &store.Permission{Role: "test-role", Resource: "resource", Action: "read"}
	if err := s.AddPermission(ctx, perm); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReassignSubject(ctx, "target-user", "merged-user"); err != nil {
		t.Fatal(err)
	}
	if err := s.RemovePermission(ctx, perm.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeRole(ctx, "merged-user", "test-role", "tenant", "wildberries:seller"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRole(ctx, "test-role"); err != nil {
		t.Fatal(err)
	}
	if err := s.SyncPolicy(ctx, []*store.Role{{Name: "new-role"}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Sync(ctx, []*store.Role{{Name: "new-role"}}, nil, nil); err != nil {
		t.Fatal(err)
	}
	backlog, err := s.outbox.Backlog(ctx)
	if err != nil || backlog.Count != 9 {
		t.Fatalf("missing committed mutation event: %+v %v", backlog, err)
	}
	rows, err := s.pool.Query(ctx, `SELECT payload FROM csar_audit_outbox`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var e audit.Event
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatal(err)
		}
		if e.Actor != "verified-user" || e.RequestID != "test-request" {
			t.Fatal("lost trusted attribution")
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	if _, err := s.pool.Exec(ctx, `DROP TABLE csar_audit_outbox`); err != nil {
		t.Fatal(err)
	}
	if err := s.AssignRole(ctx, "user", "new-role", "platform", ""); err == nil {
		t.Fatal("assignment committed without event")
	}
	roles, err := s.GetSubjectRoles(ctx, "user", "platform", "")
	if err != nil || len(roles) != 0 {
		t.Fatal("assignment survived enqueue failure")
	}
	if err := s.DeleteRole(ctx, "new-role"); err == nil {
		t.Fatal("delete committed without event")
	}
	if _, err := s.GetRole(ctx, "new-role"); err != nil {
		t.Fatal("role deletion survived rollback")
	}
}
