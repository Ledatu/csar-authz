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

	"github.com/ledatu/csar-authz/internal/config"
	"github.com/ledatu/csar-authz/internal/engine"
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
	flag.Parse()

	if err := run(sf, overrides, otlpEndpoint, otlpInsecure, logger); err != nil {
		logger.Error("fatal", "error", err)
		os.Exit(1)
	}
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

	// Load config.
	srcParams := sf.SourceParams()
	cfg, err := configload.LoadInitial(ctx, &srcParams, logger, config.LoadFromBytes)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Apply CLI overrides.
	applyOverrides(cfg, overrides)

	logger.Info("config loaded",
		"listen_addr", cfg.ListenAddr,
		"roles", len(cfg.Policy.Roles),
		"assignments", len(cfg.Policy.Assignments),
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
	defer tp.Close()

	reg := observe.NewRegistry()

	// Create store.
	var storeImpl store.Store
	var pgStore *postgres.Store
	switch cfg.Store.Backend {
	case "postgres":
		pgStore, err = postgres.New(ctx, cfg.Store.DSN, postgres.WithLogger(logger.With("component", "store")))
		if err != nil {
			return fmt.Errorf("creating postgres store: %w", err)
		}
		defer pgStore.Close()
		if err := pgStore.Migrate(ctx); err != nil {
			return fmt.Errorf("running migrations: %w", err)
		}
		storeImpl = pgStore
	default:
		storeImpl = memory.New()
	}

	// Sync policy from config into the store.
	if err := syncPolicy(ctx, storeImpl, cfg, logger); err != nil {
		return fmt.Errorf("syncing policy: %w", err)
	}

	eng := engine.New(storeImpl)
	srv := server.New(eng)

	// Build gRPC server options.
	var opts []grpc.ServerOption

	// JWT interceptor.
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
		opts = append(opts, grpc.UnaryInterceptor(validator.UnaryInterceptor()))
	}

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

	// Config watcher for hot-reload.
	if interval := sf.ParseRefreshInterval(); interval > 0 {
		src, err := configsource.BuildSource(&srcParams, logger)
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
			logger.Info("policy reloaded",
				"roles", len(newCfg.Policy.Roles),
				"assignments", len(newCfg.Policy.Assignments),
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

// syncPolicy converts config policy into store types and calls Sync.
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

	var assignments []store.ScopedAssignment
	for _, ac := range cfg.Policy.Assignments {
		scopeType := ac.ScopeType
		if scopeType == "" {
			scopeType = "platform"
		}
		for _, roleName := range ac.Roles {
			assignments = append(assignments, store.ScopedAssignment{
				Subject:   ac.Subject,
				Role:      roleName,
				ScopeType: scopeType,
				ScopeID:   ac.ScopeID,
			})
		}
	}

	return s.Sync(ctx, roles, perms, assignments)
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
	if o.reflection == "true" {
		cfg.GRPC.Reflection = true
	} else if o.reflection == "false" {
		cfg.GRPC.Reflection = false
	}
}

