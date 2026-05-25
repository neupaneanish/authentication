package telemetry

import (
	"context"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
)

func newLoggerProvider(
	ctx context.Context,
	res *resource.Resource,
	url string,
) (*sdklog.LoggerProvider, error) {
	withTimeOutContext, cancel := context.WithTimeout(ctx, timeoutInterval)
	defer cancel()

	logOpts := []otlploggrpc.Option{
		otlploggrpc.WithEndpoint(url),
		otlploggrpc.WithInsecure(),
	}

	logExporter, err := otlploggrpc.New(withTimeOutContext, logOpts...)
	if err != nil {
		return nil, err
	}

	loggerProvider := sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(
			sdklog.NewBatchProcessor(logExporter),
		),
	)
	return loggerProvider, nil
}
