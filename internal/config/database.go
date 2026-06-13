package config

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	databaseMinConnection = 5
	databaseMaxConnection = 25
	databaseConnLifeTime  = 30 * time.Minute
	databaseConnIdle      = 1 * time.Minute
	databasePingTimeout   = 5 * time.Second
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
