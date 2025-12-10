package telemetry

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	Meter metric.Meter

	shutdown func(context.Context) error
)

var (
	HTTPRequestsTotal    metric.Int64Counter
	HTTPRequestDuration  metric.Float64Histogram
	HTTPRequestsInFlight metric.Int64UpDownCounter

	AuthorizationRequests metric.Int64Counter
	ConsentDecisions      metric.Int64Counter
	TokenExchanges        metric.Int64Counter
	PKCEVerifications     metric.Int64Counter
)

type Config struct {
	ServiceName    string
	ServiceVersion string
	Environment    string
	OTLPEndpoint   string
}

func DefaultConfig() Config {
	return Config{
		ServiceName:    "authserver",
		ServiceVersion: "1.0.0",
		Environment:    "development",
		OTLPEndpoint:   "localhost:4317",
	}
}

func InitTelemetry(ctx context.Context, cfg Config) error {
	log.Println("[Telemetry] ════════════════════════════════════════════════")
	log.Println("[Telemetry] Initializing OpenTelemetry...")
	log.Printf("[Telemetry] Service: %s v%s", cfg.ServiceName, cfg.ServiceVersion)
	log.Printf("[Telemetry] OTLP Endpoint: %s", cfg.OTLPEndpoint)

	res := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(cfg.ServiceName),
		semconv.ServiceVersion(cfg.ServiceVersion),
		attribute.String("environment", cfg.Environment),
	)

	conn, err := grpc.NewClient(
		cfg.OTLPEndpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("failed to create gRPC connection: %w", err)
	}

	metricExporter, err := otlpmetricgrpc.New(ctx, otlpmetricgrpc.WithGRPCConn(conn))
	if err != nil {
		return fmt.Errorf("failed to create metric exporter: %w", err)
	}

	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExporter,
			sdkmetric.WithInterval(15*time.Second),
		)),
		sdkmetric.WithResource(res),
	)
	otel.SetMeterProvider(meterProvider)

	Meter = meterProvider.Meter(cfg.ServiceName)

	log.Println("[Telemetry] ✓ Metrics exporter configured")

	if err := initMetricInstruments(); err != nil {
		return fmt.Errorf("failed to initialize metrics: %w", err)
	}

	log.Println("[Telemetry] ✓ Metric instruments created")

	shutdown = func(ctx context.Context) error {
		log.Println("[Telemetry] Shutting down...")
		return meterProvider.Shutdown(ctx)
	}

	log.Println("[Telemetry] ════════════════════════════════════════════════")
	log.Println("[Telemetry] OpenTelemetry initialized successfully!")
	log.Println("[Telemetry] ════════════════════════════════════════════════")

	return nil
}

func Shutdown(ctx context.Context) error {
	if shutdown != nil {
		return shutdown(ctx)
	}
	return nil
}

func initMetricInstruments() error {
	var err error

	HTTPRequestsTotal, err = Meter.Int64Counter(
		"http_requests_total",
		metric.WithDescription("Total number of HTTP requests"),
		metric.WithUnit("{request}"),
	)
	if err != nil {
		return fmt.Errorf("http_requests_total: %w", err)
	}

	HTTPRequestDuration, err = Meter.Float64Histogram(
		"http_request_duration_seconds",
		metric.WithDescription("HTTP request duration in seconds"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
	)
	if err != nil {
		return fmt.Errorf("http_request_duration_seconds: %w", err)
	}

	HTTPRequestsInFlight, err = Meter.Int64UpDownCounter(
		"http_requests_in_flight",
		metric.WithDescription("Number of HTTP requests currently being processed"),
		metric.WithUnit("{request}"),
	)
	if err != nil {
		return fmt.Errorf("http_requests_in_flight: %w", err)
	}

	AuthorizationRequests, err = Meter.Int64Counter(
		"oauth_authorization_requests_total",
		metric.WithDescription("Total number of authorization requests"),
		metric.WithUnit("{request}"),
	)
	if err != nil {
		return fmt.Errorf("oauth_authorization_requests_total: %w", err)
	}

	ConsentDecisions, err = Meter.Int64Counter(
		"oauth_consent_decisions_total",
		metric.WithDescription("Total number of consent decisions by action"),
		metric.WithUnit("{decision}"),
	)
	if err != nil {
		return fmt.Errorf("oauth_consent_decisions_total: %w", err)
	}

	TokenExchanges, err = Meter.Int64Counter(
		"oauth_token_exchanges_total",
		metric.WithDescription("Total number of token exchange attempts"),
		metric.WithUnit("{exchange}"),
	)
	if err != nil {
		return fmt.Errorf("oauth_token_exchanges_total: %w", err)
	}

	PKCEVerifications, err = Meter.Int64Counter(
		"oauth_pkce_verifications_total",
		metric.WithDescription("Total number of PKCE verifications"),
		metric.WithUnit("{verification}"),
	)
	if err != nil {
		return fmt.Errorf("oauth_pkce_verifications_total: %w", err)
	}

	return nil
}

func RecordHTTPRequest(ctx context.Context, method, path string, statusCode int, duration float64) {
	attrs := []attribute.KeyValue{
		attribute.String("http_method", method),
		attribute.String("http_route", path),
		attribute.Int("http_status_code", statusCode),
	}

	HTTPRequestsTotal.Add(ctx, 1, metric.WithAttributes(attrs...))
	HTTPRequestDuration.Record(ctx, duration, metric.WithAttributes(attrs...))
}

func RecordAuthorizationRequest(ctx context.Context, clientID string, success bool) {
	attrs := []attribute.KeyValue{
		attribute.String("client_id", clientID),
		attribute.Bool("success", success),
	}
	AuthorizationRequests.Add(ctx, 1, metric.WithAttributes(attrs...))
}

func RecordConsentDecision(ctx context.Context, action string, clientID string) {
	attrs := []attribute.KeyValue{
		attribute.String("action", action),
		attribute.String("client_id", clientID),
	}
	ConsentDecisions.Add(ctx, 1, metric.WithAttributes(attrs...))
}

func RecordTokenExchange(ctx context.Context, success bool, errorType string) {
	attrs := []attribute.KeyValue{
		attribute.Bool("success", success),
	}
	if errorType != "" {
		attrs = append(attrs, attribute.String("error_type", errorType))
	}
	TokenExchanges.Add(ctx, 1, metric.WithAttributes(attrs...))
}

func RecordPKCEVerification(ctx context.Context, success bool) {
	attrs := []attribute.KeyValue{
		attribute.Bool("success", success),
	}
	PKCEVerifications.Add(ctx, 1, metric.WithAttributes(attrs...))
}

func IncrementInFlight(ctx context.Context) {
	HTTPRequestsInFlight.Add(ctx, 1)
}

func DecrementInFlight(ctx context.Context) {
	HTTPRequestsInFlight.Add(ctx, -1)
}

