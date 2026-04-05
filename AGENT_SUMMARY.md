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
- `CheckAccess` hot path for runtime authorization.
- Policy sync from config into the store at startup and during reload.
- Bootstrap assignments for initial platform and tenant access.
- Admin write/query flows for roles, members, permissions, and service-facing operations.

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
