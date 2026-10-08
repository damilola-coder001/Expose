package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/expose/expose/apps/api/internal/cache"
	"github.com/expose/expose/apps/api/internal/config"
	"github.com/expose/expose/apps/api/internal/database"
	"github.com/expose/expose/apps/api/internal/handlers"
	"github.com/expose/expose/apps/api/internal/logger"
	"github.com/expose/expose/apps/api/internal/middleware"
	"github.com/expose/expose/apps/api/internal/scanner"
	"github.com/expose/expose/apps/api/internal/storage"
)

func main() {
	cfg := config.LoadFromEnv()
	log := logger.InitLogger(cfg.LogLevel)

	log.Info("Starting EXPOSE API Server",
		slog.String("service", cfg.ServiceName),
		slog.String("version", cfg.Version),
		slog.String("env", cfg.Env),
		slog.String("port", cfg.Port),
	)

	// Initialize database client
	dbClient, err := database.NewClient(cfg.DatabaseURL)
	if err != nil {
		log.Error("Failed to parse database configuration", slog.Any("error", err))
		os.Exit(1)
	}

	// Initialize redis client
	rcClient, err := cache.NewClient(cfg.RedisURL)
	if err != nil {
		log.Error("Failed to parse redis configuration", slog.Any("error", err))
		os.Exit(1)
	}

	// Initialize persistence repository & scanner engine
	repo := storage.NewMemoryRepository()
	scannerEngine := scanner.NewEngine()
	scanHandler := handlers.NewScanHandler(scannerEngine, repo)

	// Construct HTTP Handlers
	healthHandler := handlers.NewHealthHandler(cfg, dbClient, rcClient)

	// Create ServeMux
	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler.Health)
	mux.HandleFunc("/ready", healthHandler.Ready)

	// Phase 2/4 API Routes
	mux.HandleFunc("/api/v1/scans", scanHandler.HandleScans)
	mux.HandleFunc("/api/v1/scans/", scanHandler.HandleScanByID)
	mux.HandleFunc("/api/v1/targets/", scanHandler.HandleTargetByDomain)

	// Root fallback / api index
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			handlers.WriteError(w, http.StatusNotFound, "NOT_FOUND", "The requested resource was not found")
			return
		}
		handlers.WriteJSON(w, http.StatusOK, map[string]interface{}{
			"service":   cfg.ServiceName,
			"version":   cfg.Version,
			"tagline":   "See what your website exposes.",
			"principle": "Evidence first. Intelligence second.",
			"endpoints": []string{"/health", "/ready", "/api/v1/scans", "/api/v1/targets"},
		})
	})

	// Wrap middleware chain: Recovery -> RequestID -> RequestLogger -> CORS -> mux
	handler := middleware.Recovery(
		middleware.RequestID(
			middleware.RequestLogger(
				middleware.CORS(cfg.CORSAllowedOrigins)(mux),
			),
		),
	)

	srv := &http.Server{
		Addr:         cfg.Port,
		Handler:      handler,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	// Server run context for graceful shutdown
	serverCtx, serverStopCtx := context.WithCancel(context.Background())

	// Listen for OS interrupt / terminate signals
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	go func() {
		<-sig
		log.Info("Shutting down API server gracefully...")

		shutdownCtx, cancel := context.WithTimeout(serverCtx, cfg.ShutdownGracePeriod)
		defer cancel()

		go func() {
			<-shutdownCtx.Done()
			if errors.Is(shutdownCtx.Err(), context.DeadlineExceeded) {
				log.Error("Graceful shutdown timed out... forcing exit")
			}
		}()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Error("Error during server shutdown", slog.Any("error", err))
		}
		serverStopCtx()
	}()

	log.Info("API server listening", slog.String("addr", cfg.Port))
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("Server listen failed", slog.Any("error", err))
		os.Exit(1)
	}

	<-serverCtx.Done()
	log.Info("API server stopped cleanly")
}
