package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/expose/expose/apps/api/internal/logger"
)

// RequestID attaches a unique request identifier to each incoming HTTP request context.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			bytes := make([]byte, 12)
			if _, err := rand.Read(bytes); err == nil {
				reqID = "req_" + hex.EncodeToString(bytes)
			} else {
				reqID = "req_fallback"
			}
		}

		w.Header().Set("X-Request-ID", reqID)
		ctx := context.WithValue(r.Context(), logger.RequestIDKey, reqID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
