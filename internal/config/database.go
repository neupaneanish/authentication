package config

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

func NewDatabase(
	ctx context.Context,
	url string,
) (*pgxpool.Pool, error) {
	config, configErr := pgxpool.ParseConfig(url)
	if configErr != nil {
		return nil, configErr
	}

	config.MinConns = databaseMinConnection
	config.MaxConns = databaseMaxConnection
	config.MaxConnLifetime = databaseConnLifeTime
	config.MaxConnIdleTime = databaseConnIdle

	config.HealthCheckPeriod = databasePingTimeout

	pool, poolErr := pgxpool.NewWithConfig(ctx, config)
	if poolErr != nil {
		return nil, poolErr
	}

	pingCtx, cancel := context.WithTimeout(ctx, databasePingTimeout)
	defer cancel()

	if pingErr := pool.Ping(pingCtx); pingErr != nil {
		pool.Close()
		return nil, pingErr
	}

	return pool, nil
}
