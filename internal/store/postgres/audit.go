package postgres

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
	"github.com/ledatu/csar-core/audit"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/grpcjwt"
	"github.com/ledatu/csar-core/pgutil"
)

// EnableAuditOutbox is startup-only. Do not change this contract during reload.
func (s *Store) EnableAuditOutbox(ctx context.Context) (*audit.PGOutbox, error) {
	o, err := audit.NewPGOutbox(s.pool, "csar-authz")
	if err != nil {
		return nil, err
	}
	if err := o.Migrate(ctx); err != nil {
		return nil, err
	}
	s.outbox = o
	return o, nil
}

func mutationEvent(ctx context.Context, action, targetType, targetID, scopeType, scopeID string, after any) *audit.Event {
	id, _ := gatewayctx.FromContext(ctx)
	actor := id.Subject
	if actor == "" {
		actor, _ = grpcjwt.SubjectFromContext(ctx)
	}
	if actor == "" {
		actor = "unattributed:csar-authz"
	}
	e := &audit.Event{Actor: actor, Action: action, TargetType: targetType, TargetID: targetID, ScopeType: scopeType, ScopeID: scopeID, RequestID: id.RequestID}
	if after != nil {
		// The caller supplies JSON-safe domain projections only. Marshal failures
		// are retained as invalid state so enqueue fails the entire mutation.
		body, err := json.Marshal(after)
		if err != nil {
			body = json.RawMessage("invalid audit projection")
		}
		e.AfterState = body
	}
	return e
}

func (s *Store) withAuditTx(ctx context.Context, e *audit.Event, fn func(pgx.Tx) error) error {
	return pgutil.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := fn(tx); err != nil {
			return err
		}
		if s.outbox != nil {
			return s.outbox.EnqueueTx(ctx, tx, e)
		}
		return nil
	})
}
