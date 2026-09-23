package tests

import (
	"context"
	"errors"

	"github.com/testcontainers/testcontainers-go/modules/redpanda"
)

func Redpanda() (string, func(), error) {
	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	container, err := redpanda.Run(
		ctx,
		"docker.redpanda.com/redpandadata/redpanda:v23.3.3",
	)

	if err != nil {
		cancel()
		return "", nil, err
	}

	if container == nil {
		cancel()
		return "", nil, errors.New("no container without error")
	}

	url, urlErr := container.KafkaSeedBroker(ctx)
	if urlErr != nil {
		cancel()
		return "", nil, urlErr
	}

	cleanup := func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(ctx, contextTimeout)
		defer shutdownCancel()
		_ = container.Terminate(shutdownCtx)
		cancel()
	}
	return url, cleanup, nil
}
