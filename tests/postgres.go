package tests

import (
	"context"
	"errors"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func Postgres() (string, func(), error) {
	ctx, cancel := context.WithTimeout(context.Background(), pgContextTimeout)
	container, err := postgres.Run(
		ctx,
		"postgres:18-alpine3.23",
		postgres.WithDatabase("test-db"),
		postgres.WithUsername("postgres"),
		postgres.WithPassword("postgres"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(occurrence).
				WithStartupTimeout(pgContextTimeout),
		),
	)
	if err != nil {
		cancel()
		return "", nil, err
	}

	if container == nil {
		cancel()
		return "", nil, errors.New("no container without error")
	}

	url, urlErr := container.ConnectionString(ctx, "sslmode=disable")
	if urlErr != nil {
		cancel()
		return "", nil, urlErr
	}

	cleanup := func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), pgContextTimeout)
		defer shutdownCancel()
		_ = container.Terminate(shutdownCtx)
		cancel()
	}

	return url, cleanup, nil
}
