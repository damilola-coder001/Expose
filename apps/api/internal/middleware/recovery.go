package middleware

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/expose/expose/apps/api/internal/logger"
)

// Recovery recovers from any panic in HTTP handlers, logs the stack trace, and sends a standard 500 error envelope.
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				stack := string(debug.Stack())
				log := logger.FromContext(r.Context())
				log.Error("Internal server panic recovered",
					slog.Any("panic", rec),
					slog.String("stack", stack),
				)

				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(http.StatusInternalServerError)

				resp := map[string]interface{}{
					"status": "error",
					"error": map[string]interface{}{
						"code":    "INTERNAL_SERVER_ERROR",
						"message": fmt.Sprintf("An unexpected internal error occurred: %v", rec),
					},
				}
				_ = json.NewEncoder(w).Encode(resp)
			}
		}()

		next.ServeHTTP(w, r)
	})
}
