package tests

import (
	"context"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/valkey"
	"github.com/testcontainers/testcontainers-go/wait"
)

func Valkey() (string, func(), error) {
	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)

	container, err := valkey.Run(
		ctx,
		"valkey/valkey:9-alpine3.23",
		testcontainers.WithWaitStrategy(
			wait.ForLog("Ready to accept connections").
				WithStartupTimeout(contextTimeout),
		),
	)

	return checkAndReturn(ctx, err, cancel, container)
}
