# csar-authz

Standalone RBAC authorization gRPC service for the CSAR ecosystem.

Evaluates access decisions by resolving a subject's roles (including inherited parent roles) and checking their permissions against the requested resource and action.

## Architecture

```
Client → csar (JWT validate) → csar-authz (CheckAccess) → upstream service
```

- **Policy Decision Point (PDP)** — called by the CSAR router on every request
- **RBAC model** — subjects → roles → permissions (resource pattern + action)
- **Role hierarchy** — roles inherit permissions from parent roles
- **Scoped assignments** — a subject holds roles either platform-wide (`scope_type: platform`) or inside one tenant (`scope_type: tenant`, `scope_id`)
- **Header enrichment** — returns trusted `X-Gateway-*` headers for downstream propagation (see below)

## Scope Evaluation

`CheckAccess` always loads the subject's platform-scoped roles. When the
request scope is `tenant`, the roles assigned in that tenant are merged in.
The permission match runs over the union, so a platform-wide role that holds
the requested `(resource, action)` satisfies a tenant-scoped check in every
tenant — this is how platform staff (admins, managers) reach tenant routes
without per-tenant assignments.

The decision reports which scope produced the match so backends can tell
platform staff from tenant members:

| Header | Value |
|--------|-------|
| `X-Gateway-Authz-Result` | `allow` / `deny` |
| `X-Gateway-Authz-Scope` | `platform`, `tenant`, or `platform,tenant` — scope types whose assignments produced a matched role (allow only) |
| `X-Gateway-Roles` | effective roles (direct + inherited) across the evaluated scopes |
| `X-Gateway-Subject` | the checked subject |
| `X-User-Roles`, `X-Authz-Decision`, `X-Authz-Matched-Roles` | legacy aliases kept for older backends |

The router adds `X-Gateway-Authz-Policy` (the route policy branch that
granted access) on top of these. Backends read everything through
`gatewayctx.FromContext` — `Identity.IsPlatformActor()` answers "is this
platform staff acting on a tenant?".

## Service-Facing Role Writes

The admin HTTP listener (`admin.addr`, mTLS) exposes `/svc/*` endpoints that
backend services use to assign and revoke tenant roles. A service caller is
trusted only by the gateway subject the router forwards, so two config
settings bound what that surface can do:

| Setting | Effect |
|---------|--------|
| `admin.allowed_client_cn` | Only this client certificate CN (the router's) may reach the admin API; unset accepts any CA-signed certificate |
| `admin.service_assignable_roles` | Roles `/svc` may assign or revoke in tenant scope; empty rejects every service role write |

Both are read at startup; change them via config publish plus restart.

## Quick Start

```bash
# Build
go build -o csar-authz ./cmd/csar-authz

# Run
./csar-authz -listen :9090

# With TLS
./csar-authz -listen :9090 -tls-cert cert.pem -tls-key key.pem
```

## gRPC API

**Access check (hot path):**

| RPC | Description |
|-----|-------------|
| `CheckAccess` | Evaluate subject + resource + action → allow/deny |

**Policy management:**

| RPC | Description |
|-----|-------------|
| `CreateRole` / `DeleteRole` / `GetRole` / `ListRoles` | Manage roles with optional parent hierarchy |
| `AssignRole` / `RevokeRole` / `ListSubjectRoles` | Bind subjects to roles |
| `AddPermission` / `RemovePermission` / `ListRolePermissions` | Bind permissions to roles |

## Resource Matching

Permissions use URL patterns with wildcard support:

| Pattern | Matches | Doesn't match |
|---------|---------|---------------|
| `/api/v1/users` | `/api/v1/users` | `/api/v1/users/123` |
| `/api/v1/users/*` | `/api/v1/users/123` | `/api/v1/users/123/posts` |
| `/api/v1/**` | `/api/v1`, `/api/v1/users/123/posts` | `/api/v2/users` |
| `/**` | everything | — |

Action `*` matches any HTTP method.

## Example (grpcurl)

```bash
# Create roles
grpcurl -plaintext -d '{"name":"viewer","description":"Read-only"}' \
  localhost:9090 csar.authz.v1.AuthzService/CreateRole

grpcurl -plaintext -d '{"name":"editor","description":"Can edit","parents":["viewer"]}' \
  localhost:9090 csar.authz.v1.AuthzService/CreateRole

# Add permissions
grpcurl -plaintext -d '{"role":"viewer","resource":"/api/**","action":"GET"}' \
  localhost:9090 csar.authz.v1.AuthzService/AddPermission

grpcurl -plaintext -d '{"role":"editor","resource":"/api/v1/posts/**","action":"PUT"}' \
  localhost:9090 csar.authz.v1.AuthzService/AddPermission

# Assign role
grpcurl -plaintext -d '{"subject":"user-1","role":"editor"}' \
  localhost:9090 csar.authz.v1.AuthzService/AssignRole

# Check access — allowed (GET inherited from viewer)
grpcurl -plaintext -d '{"subject":"user-1","resource":"/api/v1/users","action":"GET"}' \
  localhost:9090 csar.authz.v1.AuthzService/CheckAccess

# Check access — denied (no DELETE permission)
grpcurl -plaintext -d '{"subject":"user-1","resource":"/api/v1/posts/123","action":"DELETE"}' \
  localhost:9090 csar.authz.v1.AuthzService/CheckAccess
```

## Project Structure

```
cmd/csar-authz/main.go            Entry point, gRPC server, TLS, graceful shutdown
internal/
  engine/engine.go                 RBAC engine: role hierarchy + permission evaluation
  engine/matcher.go                URL pattern matching (*, ** wildcards)
  server/server.go                 gRPC AuthzServiceServer implementation
  store/store.go                   Store interface (roles, permissions, assignments)
  store/memory/memory.go           Thread-safe in-memory store
proto/authz/v1/authz.proto        Service definition (11 RPCs)
```

## Testing

```bash
go test ./... -v
```

## Transactional audit outbox (activation gated)

`audit_outbox_enabled: false` is the default. Enabling requires PostgreSQL and a
configured router-backed `audit` STS transport, and requires a restart. Deploy
compatible core and confirmed-ingest audit images first. Mixed old ingest instances
can acknowledge before durable acceptance; do not enable producers until all are upgraded.

Business writes and outbox entries share one transaction. Failed enqueue rolls back
the mutation. Relays use SKIP LOCKED, service-scoped claims and 60s fenced leases;
a 30s send plus 5s finish fits that lease. A missing/lost receipt retains the original
ID, timestamp and payload for retry. One bounded sender per replica owns its router
transport. Network calls never hold the business transaction. Pending copies are
removed only after confirmed acceptance. Already-issued tokens and business behavior
retain their existing semantics. Outbox schema is created only when the mode is enabled.

Metrics are audit_outbox_pending_events, audit_outbox_oldest_age_seconds and
audit_outbox_scrape_success. Database-query errors omit backlog values and report
scrape failure rather than a false zero. Configure alert delivery separately.

Coverage: PostgreSQL role create/delete, assignment grant/revoke, permission
add/remove, subject reassignment, policy sync/full replacement and bootstrap grants.
HTTP attribution uses trusted gateway context; authenticated gRPC uses its verified
subject. Config/bootstrap activity has an explicit system actor; otherwise the event
is marked unattributed. Successful idempotent grant/revoke attempts are also audited.
Post-commit duplicates are suppressed only for covered HTTP action names. The memory
backend retains its existing best-effort behavior and cannot enable this mode.
