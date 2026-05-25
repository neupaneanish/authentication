package tests

import (
	"context"
	"errors"
	"time"

	"github.com/testcontainers/testcontainers-go"
)

const (
	contextTimeout = 60 * time.Second
)

func checkAndReturn(
	ctx context.Context,
	err error,
	cancel context.CancelFunc,
	container testcontainers.Container,
) (string, func(), error) {
	if err != nil {
		cancel()
		return "", nil, err
	}

	if container == nil {
		cancel()
		return "", nil, errors.New("no container without error")
	}

	endpoint, endpointErr := container.Endpoint(ctx, "")
	if endpointErr != nil {
		terminateCtx, terminateCancel := context.WithTimeout(
			context.Background(),
			contextTimeout,
		)
		defer terminateCancel()
		_ = container.Terminate(terminateCtx)
		cancel()
		return "", nil, endpointErr
	}

	cleanup := func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), contextTimeout)
		defer shutdownCancel()
		_ = container.Terminate(shutdownCtx)
		cancel()
	}

	return endpoint, cleanup, nil
}
