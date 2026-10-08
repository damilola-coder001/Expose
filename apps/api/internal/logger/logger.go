package logger

import (
	"context"
	"log/slog"
	"os"
	"strings"
)

type contextKey string

const RequestIDKey contextKey = "request_id"

// InitLogger initializes the global slog default logger with structured JSON formatting.
func InitLogger(levelStr string) *slog.Logger {
	var level slog.Level
	switch strings.ToLower(levelStr) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	handler := slog.NewJSONHandler(os.Stdout, opts)
	log := slog.New(handler)
	slog.SetDefault(log)
	return log
}

// FromContext extracts request ID and attaches it to structured log entries.
func FromContext(ctx context.Context) *slog.Logger {
	log := slog.Default()
	if ctx == nil {
		return log
	}
	if reqID, ok := ctx.Value(RequestIDKey).(string); ok && reqID != "" {
		return log.With(slog.String("request_id", reqID))
	}
	return log
}
