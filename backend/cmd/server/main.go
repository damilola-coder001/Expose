package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/expose/expose-backend/internal/api"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	handler := api.NewAPIHandler()
	mux := http.NewServeMux()

	// Register API endpoints
	mux.HandleFunc("/health", handler.HealthCheck)
	mux.HandleFunc("/api/v1/scans", handler.HandleScans)
	mux.HandleFunc("/api/v1/scans/async", handler.HandleScanAsync)
	mux.HandleFunc("/api/v1/scans/", handler.HandleScanByID)

	// Wrap with standard CORS middleware for Next.js frontend
	corsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		mux.ServeHTTP(w, r)
	})

	server := &http.Server{
		Addr:         fmt.Sprintf(":%s", port),
		Handler:      corsHandler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	// Graceful shutdown handling
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("[EXPOSE] Security Scanning Engine (Go) listening on http://0.0.0.0:%s", port)
		log.Printf("[EXPOSE] Policy: Only scan websites you own or are authorized to test.")
		log.Printf("[EXPOSE] Principle: Evidence first. Intelligence second.")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	<-stop
	log.Println("[EXPOSE] Initiating graceful shutdown...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("[EXPOSE] Forced shutdown: %v", err)
	}
	log.Println("[EXPOSE] Engine stopped cleanly.")
}
