## Per-service list and role capabilities (U10, opt-in)

The full receiver enforces enabled service policy on the existing role grant/
revoke, subject scope list, tenant assignment list and bounded assignment query
wire APIs. Verified gateway mTLS and classified STS caller, exact service and
operation are mandatory; unknown combinations deny with no svc-prefix fallback.
Subject listing requires explicit request-bound owner matching or background
capability and filters results to configured scope mappings. Tenant IDs must map
exactly to permitted profile bindings before engine access. Mutations intersect
operation roles with both the immutable startup and current global service-role
ceiling, preserving protected-role checks and transactional audit. Enabled routes
have five-second operation contexts and no-store responses. Startup policy, peer/
listener and role ceiling changes require restart. Disabled/omitted policies keep
legacy compatibility until consumer migration/U17. Buyers' fixed compatibility
operation remains for U11 migration; no deployed policy or route is activated.

## Generic service decision receiver (U03, source only)

`POST /svc/decisions/check` is registered only for enabled, validated
`service_policies`, on a pinned verified admin mTLS listener. The request selects
a configured profile/audience and 1–100 distinct namespace/resource refs; fixed
permission and scope mappings stay in configuration and the existing engine
evaluates current authority. Verified gateway service/STS identity plus exact
per-service decide/profile/subject-mode capability is mandatory. Request-bound
owner attribution narrows the target, never substitutes for consent or data
authority; explicit background checks support a durable actor. Results are fully
correlated permissions, not access grants. Engine uncertainty, expiry/cancellation
and invalid candidates release no partial results. No decision cache is added.
The handler owns its startup policy; reload rejects service-policy or enabled
ingress changes before syncing any policy. Buyers compatibility remains until consumer migration/U17; U10 above now
constrains the existing service role/list endpoints when policies are enabled.
This pins the merged Core receiver prerequisite; no route, deployed config,
credential, Redis, database schema or production behavior is activated.

## Uniform caller envelope compatibility — source only

Pins merged Core34bbe3cf so verified caller/origin envelopes can carry bounded
HTTPS client metadata identifiers without service-local validation copies.
Identity, ownership, tenant authorization and credential audiences retain their
existing checks. This is a receiver compatibility prerequisite before enabling
automatic MCP onboarding; it changes no route, feature flag or deployment.

# csar-authz Agent Summary

## Role In Prod
`csar-authz` is the RBAC policy decision point for the CSAR ecosystem. In prod it serves gRPC for `CheckAccess` and policy management, plus an admin HTTP surface for service-facing write/query operations that are proxied through the router.

## Runtime Entry Points
- `cmd/csar-authz/main.go` wires config, store, policy sync, interceptors, TLS, health, and the admin HTTP server.
- `internal/server/server.go` implements the gRPC service.
- `internal/admin/*` owns the admin HTTP surface and its capability model.
- `internal/engine/*` evaluates roles, inheritance, and permission matching.

## Trust And Auth Model
- End-user JWTs are validated at the router before authz is consulted.
- The gRPC path can validate authn tokens via JWKS and TLS settings from config.
- The admin HTTP API requires mTLS, and optional CN pinning is enforced in-process.
- Requests read `gatewayctx` identity only after the router or trusted middleware has established the boundary.

## Critical Flows
- Built-in admin grants are validated once at the engine assignment boundary:
  `tenant_admin` requires tenant scope with a bounded literal ID, without empty
  colon-separated segments, wildcards, paths or control characters;
  `platform_admin` requires platform scope with an empty ID. HTTP, gRPC, service,
  and bootstrap grants use this boundary. Config grants are validated before
  policy sync. Existing legacy scope assignments remain exact and revocable.
- `CheckAccess` hot path for runtime authorization.
- Policy sync from config into the store at startup and during reload.
- Bootstrap assignments for initial platform and tenant access.
- Admin write/query flows for roles, members, permissions, and service-facing operations.
- `POST /svc/assignments/query` returns tenant assignments for up to 1000 tenants in one call; the legacy identity sync in aurumskynet-campaigns uses it instead of one `GET /svc/tenants/{id}/assignments` per cabinet. Each row carries `assigned_at`, which the sync uses to classify grants it may later revoke.

## Dependencies
- PostgreSQL or the in-memory store, depending on configuration.
- Authn JWKS/TLS settings for gRPC validation.
- Router-backed audit client for admin activity when configured.
- Manifest-driven config and health probe sidecar.

## Config And Secrets
- Sensitive values include authn JWKS URL, authn TLS material, store DSN, admin TLS cert/key/client CA, audit router settings, and bootstrap assignments.
- `cfg.Admin.AllowedClientCN` is security-sensitive because it narrows who can use the admin HTTP API.
- gRPC reflection is config-controlled and should stay disabled unless there is a clear operational need.

## Audit Hotspots
- `/admin/audit` is exposed in the API but is currently a dead path when the audit store is not wired, so the capability surface and runtime behavior can drift.
- Config reload is partial: some runtime config updates are not fully rebound, including admin CN policy and outbound wiring.
- The `svc:*` admin HTTP surface is broad and relies on router routing plus mTLS rather than a strong in-repo service allowlist.

## First Files To Read
- `cmd/csar-authz/main.go`
- `internal/server/server.go`
- `internal/grpcauthz/interceptor.go`
- `internal/admin/handler.go`
- `internal/admin/service.go`
- `internal/admin/members.go`
- `internal/engine/engine.go`
- `README.md`

## DRY / Extraction Candidates
- The trust/mTLS gating pattern used by the admin HTTP API is a reusable shape if more services need trusted operator endpoints.
- Keep authorization contract types in `csar-proto`; do not duplicate authz RPC schemas locally.

## Required Quality Gates
- `go build ./...`
- `go test ./... -count=1`
- `golangci-lint run ./...`

## Transactional audit coverage (activation pending, October 8)
- Startup-only `audit_outbox_enabled` defaults to false and requires PostgreSQL
  plus configured router transport. It covers role create/delete, assignment
  grant/revoke, permission add/remove, subject reassignment and policy sync/
  replacement on both HTTP and gRPC paths. Memory-store behavior is unchanged.
- Each covered mutation and its core outbox event share one transaction; enqueue
  failure rolls back the business change. Relays retain identical events until
  confirmed acceptance. Startup/bootstrap actions have explicit system actors;
  normal events derive trusted gateway or verified gRPC identity.
- Policy sync/replacement events record item counts, not the complete policy or
  a reconstructable before/after diff. Idempotent grant/revoke attempts are
  recorded as successful attempts. Do not interpret them as proof of a row change.
- Duplicate HTTP async events are suppressed only for known covered actions in
  outbox mode. Relay startup is independent of admin HTTP enablement.
- See `internal/store/postgres/audit.go`, guarded `audit_integration_test.go`,
  `cmd/csar-authz/main.go` and README. Production activation is still pending.

## Buyers delegated dispatch check (source only)

`POST /svc/buyers/dispatch-authority` is restricted to gateway subject
`svc:aurumskynet-buyers` on the existing router/mTLS service surface. Canonical
seller and user UUIDs select only `campaign_module / buyers.write` in the
`wildberries:<seller>` tenant. The caller cannot choose permissions. Each call
uses the current engine decision, has no application decision cache, and never
returns role lists or changes assignments. Buyers calls through the proposed
CSAR `/svc/authz/buyers/dispatch-authority` route. Deployment is separate.
