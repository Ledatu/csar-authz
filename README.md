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
