package telemetry

import (
	"context"

	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
)

func newResource(
	ctx context.Context,
	serviceName string,
	environment string,
) (*resource.Resource, error) {
	res, err := resource.New(
		ctx,
		resource.WithProcess(),
		resource.WithHost(),
		resource.WithHostID(),
		resource.WithOS(),
		resource.WithContainer(),
		resource.WithContainerID(),
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.DeploymentEnvironmentName(environment),
		),
	)

	if err != nil {
		return nil, err
	}

	return res, nil
}
