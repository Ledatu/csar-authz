// Command csar-authz starts the RBAC authorization gRPC service.
//
// Usage:
//
//	csar-authz -config config.yaml [-config-refresh-interval 60s]
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ledatu/csar-core/configload"
	"github.com/ledatu/csar-core/configsource"
	"github.com/ledatu/csar-core/grpcjwt"
	"github.com/ledatu/csar-core/health"
	"github.com/ledatu/csar-core/httpserver"
	"github.com/ledatu/csar-core/logutil"
	"github.com/ledatu/csar-core/observe"
	"github.com/ledatu/csar-core/tlsx"

	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/httpmiddleware"

	"github.com/ledatu/csar-core/audit"

	"github.com/ledatu/csar-authz/internal/admin"
	"github.com/ledatu/csar-authz/internal/config"
	"github.com/ledatu/csar-authz/internal/engine"
	"github.com/ledatu/csar-authz/internal/grpcauthz"
	"github.com/ledatu/csar-authz/internal/server"
	"github.com/ledatu/csar-authz/internal/store"
	"github.com/ledatu/csar-authz/internal/store/memory"
	"github.com/ledatu/csar-authz/internal/store/postgres"
	pb "github.com/ledatu/csar-proto/csar/authz/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

// Version is set at build time via ldflags.
var Version = "dev"

// cliOverrides holds flag values that override config file settings.
type cliOverrides struct {
	listen     string
	tlsCert    string
	tlsKey     string
	reflection string // "true" / "false" / "" (unset)
}

func main() {
	inner := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	logger := slog.New(logutil.NewRedactingHandler(inner))

	sf := configload.NewSourceFlags()
	sf.RegisterFlags(flag.CommandLine)

	var overrides cliOverrides
	otlpEndpoint := ""
	otlpInsecure := false
	flag.StringVar(&otlpEndpoint, "otlp-endpoint", otlpEndpoint, "OTLP gRPC endpoint for tracing (empty to disable)")
	flag.BoolVar(&otlpInsecure, "otlp-insecure", otlpInsecure, "use insecure connection for OTLP")
	flag.StringVar(&overrides.listen, "listen", "", "override listen address from config")
	flag.StringVar(&overrides.tlsCert, "tls-cert", "", "override TLS certificate file from config")
	flag.StringVar(&overrides.tlsKey, "tls-key", "", "override TLS key file from config")
	flag.StringVar(&overrides.reflection, "reflection", "", "override gRPC reflection from config (true/false)")
	var bootstrapAdmin string
	flag.StringVar(&bootstrapAdmin, "bootstrap-admin", "", "assign platform_admin to a subject and exit")
	flag.Parse()

	var err error
	if bootstrapAdmin != "" {
		err = runBootstrap(sf, overrides, bootstrapAdmin, logger)
	} else {
		err = run(sf, overrides, otlpEndpoint, otlpInsecure, logger)
	}
	if err != nil {
		logger.Error("fatal", "error", err)
		os.Exit(1)
	}
}

// loadConfig loads the authz config from the configured source and applies CLI overrides.
func loadConfig(ctx context.Context, sf *configload.SourceFlags, overrides cliOverrides, logger *slog.Logger) (*config.Config, error) {
	srcParams := sf.SourceParams()
	cfg, err := configload.LoadInitial(ctx, &srcParams, logger, config.LoadFromBytes)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}
	applyOverrides(cfg, overrides)
	return cfg, nil
}

// storeResult bundles a store with its optional postgres handle (needed for
// health checks, audit, and pool sharing) and a cleanup function.
type storeResult struct {
	store   store.Store
	pgStore *postgres.Store
	cleanup func()
}

// createStore creates the persistence backend, runs migrations, and returns
// the store with a cleanup function.
func createStore(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*storeResult, error) {
	switch cfg.Store.Backend {
	case "postgres":
		pgStore, err := postgres.New(ctx, cfg.Store.DSN, postgres.WithLogger(logger.With("component", "store")))
		if err != nil {
			return nil, fmt.Errorf("creating postgres store: %w", err)
		}
		if err := pgStore.Migrate(ctx); err != nil {
			pgStore.Close()
			return nil, fmt.Errorf("running migrations: %w", err)
		}
		return &storeResult{store: pgStore, pgStore: pgStore, cleanup: pgStore.Close}, nil
	default:
		return &storeResult{store: memory.New(), cleanup: func() {}}, nil
	}
}

// runBootstrap assigns platform_admin to the given subject and exits.
func runBootstrap(sf *configload.SourceFlags, overrides cliOverrides, subject string, logger *slog.Logger) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg, err := loadConfig(ctx, sf, overrides, logger)
	if err != nil {
		return err
	}

	sr, err := createStore(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer sr.cleanup()

	if err := syncPolicy(ctx, sr.store, cfg, logger); err != nil {
		return fmt.Errorf("syncing policy: %w", err)
	}

	const roleName = "platform_admin"
	if err := sr.store.AssignRole(ctx, subject, roleName, "platform", ""); err != nil {
		return fmt.Errorf("assigning %s to %q: %w", roleName, subject, err)
	}

	roles, err := sr.store.GetSubjectRoles(ctx, subject, "platform", "")
	if err != nil {
		return fmt.Errorf("reading back roles for %q: %w", subject, err)
	}

	logger.Info("bootstrap complete",
		"subject", subject,
		"platform_roles", roles,
	)
	return nil
}

func run(
	sf *configload.SourceFlags,
	overrides cliOverrides,
	otlpEndpoint string,
	otlpInsecure bool,
	logger *slog.Logger,
) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg, err := loadConfig(ctx, sf, overrides, logger)
	if err != nil {
		return err
	}

	logger.Info("config loaded",
		"listen_addr", cfg.ListenAddr,
		"roles", len(cfg.Policy.Roles),
		"authn_enabled", cfg.Authn.Enabled,
	)

	// --- Observability ---
	tp, err := observe.InitTracer(ctx, observe.TraceConfig{
		ServiceName:    "csar-authz",
		ServiceVersion: Version,
		Endpoint:       otlpEndpoint,
		Insecure:       otlpInsecure,
	})
	if err != nil {
		return fmt.Errorf("initializing tracer: %w", err)
	}
	defer func() { _ = tp.Close() }()

	reg := observe.NewRegistry()

	sr, err := createStore(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer sr.cleanup()
	storeImpl := sr.store
	pgStore := sr.pgStore

	// Sync policy from config into the store.
	if err := syncPolicy(ctx, storeImpl, cfg, logger); err != nil {
		return fmt.Errorf("syncing policy: %w", err)
	}

	eng := engine.New(storeImpl)
	srv := server.New(eng)

	// Build gRPC server options.
	var opts []grpc.ServerOption

	// Interceptor chain: JWT (authn) → authz.
	var interceptors []grpc.UnaryServerInterceptor
	if cfg.Authn.Enabled {
		validator, err := grpcjwt.NewValidator(&grpcjwt.Config{
			JWKSURL:       cfg.Authn.JWKSURL,
			PublicKeyFile: cfg.Authn.PublicKeyFile,
			Issuer:        cfg.Authn.Issuer,
			Audience:      cfg.Authn.Audience,
			ClockSkew:     cfg.Authn.ClockSkew.Duration,
			SubjectClaim:  cfg.Authn.SubjectClaim,
			CacheTTL:      cfg.Authn.CacheTTL.Duration,
		}, logger.With("component", "authn"))
		if err != nil {
			return fmt.Errorf("initializing authn: %w", err)
		}
		interceptors = append(interceptors, validator.UnaryInterceptor())
	}
	authzInterceptor := grpcauthz.NewInterceptor(eng, &cfg.Admin, cfg.Authn.Enabled)
	interceptors = append(interceptors, authzInterceptor.UnaryInterceptor())
	opts = append(opts, grpc.ChainUnaryInterceptor(interceptors...))

	// TLS via tlsx.
	if cfg.TLS.IsEnabled() {
		tc, err := tlsx.NewServerTLSConfig(tlsx.ServerConfig{
			CertFile:     cfg.TLS.CertFile,
			KeyFile:      cfg.TLS.KeyFile,
			ClientCAFile: cfg.TLS.ClientCAFile,
			MinVersion:   cfg.TLS.MinVersion,
		})
		if err != nil {
			return fmt.Errorf("TLS config: %w", err)
		}
		opts = append(opts, grpc.Creds(credentials.NewTLS(tc)))
		logger.Info("TLS enabled")
	}

	grpcServer := grpc.NewServer(opts...)
	pb.RegisterAuthzServiceServer(grpcServer, srv)

	if cfg.GRPC.Reflection {
		reflection.Register(grpcServer)
		logger.Info("gRPC server reflection enabled")
	}

	// --- Health and metrics HTTP sidecar ---
	healthMux := http.NewServeMux()
	healthMux.Handle("/health", health.Handler(Version))
	rc := health.NewReadinessChecker(Version, true)
	if pgStore != nil {
		pool := pgStore.Pool()
		rc.Register("postgres", func() health.CheckStatus {
			if err := pool.Ping(context.Background()); err != nil {
				return health.CheckStatus{Status: "fail", Detail: err.Error()}
			}
			return health.CheckStatus{Status: "ok"}
		})
	}
	healthMux.Handle("/readiness", rc.Handler())
	healthMux.Handle("/metrics", observe.MetricsHandler(reg))

	healthSrv, err := httpserver.New(&httpserver.Config{
		Addr:         cfg.HealthAddr,
		Handler:      healthMux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}, logger.With("component", "health"))
	if err != nil {
		return fmt.Errorf("creating health server: %w", err)
	}
	go func() {
		if err := healthSrv.ListenAndServe(); err != nil {
			logger.Error("health server error", "error", err)
		}
	}()
	logger.Info("health/metrics sidecar started", "addr", cfg.HealthAddr)

	// --- Admin HTTP API ---
	var adminHandler *admin.Handler
	if cfg.Admin.Enabled {
		if cfg.Admin.TLS.ClientCAFile == "" {
			return fmt.Errorf("admin.tls.client_ca_file is required when admin API is enabled — " +
				"the admin API uses mTLS to verify that requests originate from a trusted gateway")
		}

		var auditStore audit.Store
		if pgStore != nil {
			pgAudit := audit.NewPostgresStore(pgStore.Pool(), logger.With("component", "audit"))
			if err := pgAudit.Migrate(ctx); err != nil {
				return fmt.Errorf("running audit migrations: %w", err)
			}
			auditStore = pgAudit
			logger.Info("audit store initialized (shared postgres pool)")
		}

		adminHandler = admin.New(eng, auditStore, logger.With("component", "admin"), &cfg.Admin)

		adminMux := http.NewServeMux()
		adminHandler.RegisterRoutes(adminMux)
		adminMux.Handle("GET /health", health.Handler(Version))
		adminMux.Handle("GET /readiness", rc.Handler())

		trustFn := func(r *http.Request) error {
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				return fmt.Errorf("client certificate required for admin API")
			}
			if cn := cfg.Admin.AllowedClientCN; cn != "" {
				peer := r.TLS.PeerCertificates[0]
				if peer.Subject.CommonName != cn {
					return fmt.Errorf("client CN %q not authorized for admin API", peer.Subject.CommonName)
				}
			}
			return nil
		}

		adminStack := httpmiddleware.Chain(
			httpmiddleware.RequestID,
			httpmiddleware.AccessLog(logger.With("component", "admin")),
			httpmiddleware.Recover(logger),
			httpmiddleware.MaxBodySize(1<<20),
			gatewayctx.TrustedMiddleware(trustFn),
		)

		adminTLS := &tlsx.ServerConfig{
			CertFile:     cfg.Admin.TLS.CertFile,
			KeyFile:      cfg.Admin.TLS.KeyFile,
			ClientCAFile: cfg.Admin.TLS.ClientCAFile,
			MinVersion:   cfg.Admin.TLS.MinVersion,
		}

		adminSrv, err := httpserver.New(&httpserver.Config{
			Addr:         cfg.Admin.Addr,
			Handler:      adminStack(adminMux),
			TLS:          adminTLS,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 30 * time.Second,
		}, logger.With("component", "admin-server"))
		if err != nil {
			return fmt.Errorf("creating admin server: %w", err)
		}
		go func() {
			if err := adminSrv.ListenAndServe(); err != nil {
				logger.Error("admin server error", "error", err)
			}
		}()
		logger.Info("admin HTTP API started", "addr", cfg.Admin.Addr)
	}

	// Config watcher for hot-reload.
	if interval := sf.ParseRefreshInterval(); interval > 0 {
		watchParams := sf.SourceParams()
		src, err := configsource.BuildSource(&watchParams, logger)
		if err != nil {
			return fmt.Errorf("building config source for watcher: %w", err)
		}

		applyFn := func(_ context.Context, data []byte) (bool, error) {
			newCfg, err := config.LoadFromBytes(data)
			if err != nil {
				return false, err
			}
			if err := syncPolicy(ctx, storeImpl, newCfg, logger); err != nil {
				return false, fmt.Errorf("syncing policy: %w", err)
			}
			authzInterceptor.SetConfig(&newCfg.Admin)
			if adminHandler != nil {
				adminHandler.SetConfig(&newCfg.Admin)
			}
			logger.Info("policy reloaded",
				"roles", len(newCfg.Policy.Roles),
			)
			return true, nil
		}

		watcher := configsource.NewConfigWatcher(src, applyFn, logger.With("component", "config_watcher"), sf.WatcherOptions()...)
		go watcher.RunPeriodicWatch(ctx, interval)
		logger.Info("config watcher started", "interval", interval)
	}

	// Start listening.
	lis, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", cfg.ListenAddr, err)
	}

	logger.Info("csar-authz starting", "address", cfg.ListenAddr, "store", cfg.Store.Backend)

	// Graceful shutdown.
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		logger.Info("shutting down", "signal", fmt.Sprintf("%v", sig))
		grpcServer.GracefulStop()
	}()

	if err := grpcServer.Serve(lis); err != nil {
		return fmt.Errorf("gRPC server error: %w", err)
	}
	return nil
}

// syncPolicy converts config roles and permissions into store types and
// calls SyncPolicy. Assignments are runtime-managed and not touched here.
func syncPolicy(ctx context.Context, s store.Store, cfg *config.Config, logger *slog.Logger) error {
	var roles []*store.Role
	var perms []*store.Permission

	for _, rc := range cfg.Policy.Roles {
		roles = append(roles, &store.Role{
			Name:        rc.Name,
			Description: rc.Description,
			Parents:     rc.Parents,
		})
		for _, pc := range rc.Permissions {
			perms = append(perms, &store.Permission{
				Role:     rc.Name,
				Resource: pc.Resource,
				Action:   pc.Action,
			})
		}
	}

	return s.SyncPolicy(ctx, roles, perms)
}

func applyOverrides(cfg *config.Config, o cliOverrides) {
	if o.listen != "" {
		cfg.ListenAddr = o.listen
	}
	if o.tlsCert != "" {
		cfg.TLS.CertFile = o.tlsCert
	}
	if o.tlsKey != "" {
		cfg.TLS.KeyFile = o.tlsKey
	}
	switch o.reflection {
	case "true":
		cfg.GRPC.Reflection = true
	case "false":
		cfg.GRPC.Reflection = false
	}
}
