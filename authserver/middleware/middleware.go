package middleware

import (
	"net/http"
	"time"

	"pkce1/authserver/telemetry"
)

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func TelemetryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		start := time.Now()

		if telemetry.HTTPRequestsInFlight != nil {
			telemetry.IncrementInFlight(ctx)
			defer telemetry.DecrementInFlight(ctx)
		}

		wrapped := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next.ServeHTTP(wrapped, r)

		if telemetry.HTTPRequestsTotal != nil {
			duration := time.Since(start).Seconds()
			telemetry.RecordHTTPRequest(ctx, r.Method, r.URL.Path, wrapped.statusCode, duration)
		}
	})
}
