package telemetry

import (
	"context"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func newTracerProvider(
	ctx context.Context,
	res *resource.Resource,
	url string,
) (*sdktrace.TracerProvider, error) {
	withTimeOutContext, cancel := context.WithTimeout(ctx, timeoutInterval)
	defer cancel()

	traceOpts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(url),
		otlptracegrpc.WithInsecure(),
	}

	traceExporter, err := otlptracegrpc.New(withTimeOutContext, traceOpts...)
	if err != nil {
		return nil, err
	}

	traceProvider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExporter),
		sdktrace.WithResource(res),
	)

	return traceProvider, nil
}
