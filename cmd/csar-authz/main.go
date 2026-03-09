// Command csar-authz starts the RBAC authorization gRPC service.
//
// Usage:
//
//	csar-authz [-listen :9090] [-tls-cert cert.pem] [-tls-key key.pem]
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/ledatu/csar-authz/internal/engine"
	"github.com/ledatu/csar-authz/internal/server"
	"github.com/ledatu/csar-authz/internal/store/memory"
	pb "github.com/ledatu/csar-authz/proto/authz/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

func main() {
	listen := flag.String("listen", ":9090", "gRPC listen address")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file (PEM)")
	tlsKey := flag.String("tls-key", "", "TLS private key file (PEM)")
	enableReflection := flag.Bool("reflection", true, "enable gRPC server reflection")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Initialize store and engine.
	store := memory.New()
	eng := engine.New(store)
	srv := server.New(eng)

	// Build gRPC server options.
	var opts []grpc.ServerOption
	if *tlsCert != "" && *tlsKey != "" {
		cert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil {
			logger.Error("failed to load TLS credentials", "error", err)
			os.Exit(1)
		}
		opts = append(opts, grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		})))
		logger.Info("TLS enabled")
	}

	grpcServer := grpc.NewServer(opts...)
	pb.RegisterAuthzServiceServer(grpcServer, srv)

	if *enableReflection {
		reflection.Register(grpcServer)
		logger.Info("gRPC server reflection enabled")
	}

	// Start listening.
	lis, err := net.Listen("tcp", *listen)
	if err != nil {
		logger.Error("failed to listen", "address", *listen, "error", err)
		os.Exit(1)
	}

	logger.Info("csar-authz starting",
		"address", *listen,
		"store", "memory",
	)

	// Graceful shutdown on SIGINT/SIGTERM.
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		logger.Info("shutting down", "signal", fmt.Sprintf("%v", sig))
		grpcServer.GracefulStop()
	}()

	if err := grpcServer.Serve(lis); err != nil {
		logger.Error("gRPC server error", "error", err)
		os.Exit(1)
	}
}
