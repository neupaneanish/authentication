package tests

import (
	"context"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func OpenTelemetry() (string, func(), error) {
	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)

	container, err := testcontainers.GenericContainer(ctx,
		testcontainers.GenericContainerRequest{
			Image:        "otel/opentelemetry-collector:latest",
			ExposedPorts: []string{"4317/tcp"},
			WaitingFor:   wait.ForLog("Everything is ready. Begin running and processing data."),
			Started:      true,
		})

	return checkAndReturn(ctx, err, cancel, container)
}
