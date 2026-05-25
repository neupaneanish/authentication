package telemetry

import (
	"context"

	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
)

func newMeterProvider(
	ctx context.Context,
	res *resource.Resource,
	url string,
) (*metric.MeterProvider, error) {
	withTimeOutContext, cancel := context.WithTimeout(ctx, timeoutInterval)
	defer cancel()

	metricOpts := []otlpmetricgrpc.Option{
		otlpmetricgrpc.WithEndpoint(url),
		otlpmetricgrpc.WithInsecure(),
	}

	metricExporter, err := otlpmetricgrpc.New(withTimeOutContext, metricOpts...)
	if err != nil {
		return nil, err
	}

	reader := metric.NewPeriodicReader(metricExporter, metric.WithInterval(metricInterval))

	metricProvider := metric.NewMeterProvider(
		metric.WithResource(res),
		metric.WithReader(reader),
	)

	return metricProvider, nil
}
