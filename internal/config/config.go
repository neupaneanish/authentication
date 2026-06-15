package config

import (
	"context"
	"log/slog"

	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/valkey-io/valkey-go"
	"neupaneanish.com.np/api/internal/repository"
)

type Config struct {
	Pool        *pgxpool.Pool
	Client      valkey.Client
	Logger      *slog.Logger
	Port        string
	Environment string
	ServiceName string
	Jwt         *JWT
	TwoFactor   *TwoFactor
	RateLimiter *RateLimiter
	Repository  repository.Querier
	Domain      *Domain
	Worker      *asynq.Client
}

func NewConfig(
	ctx context.Context,
	env *Env,
	logger *slog.Logger,
) (*Config, error) {
	pool, poolErr := NewDatabase(ctx, env.DatabaseURL)
	if poolErr != nil {
		return nil, poolErr
	}

	client, clientErr := NewValkey(ctx, env.ValkeyURL)
	if clientErr != nil {
		return nil, clientErr
	}

	jwt, jwtErr := NewJWT(env.JWTKey, env.Issuer)
	if jwtErr != nil {
		return nil, jwtErr
	}

	twoFactor, twoFactorErr := NewTwoFactor(env.TwoFactorKey, env.Issuer)
	if twoFactorErr != nil {
		return nil, twoFactorErr
	}

	rateLimiter, rateLimiterErr := NewRateLimiter(client)
	if rateLimiterErr != nil {
		return nil, rateLimiterErr
	}

	worker, workerErr := NewWorker(env.ValkeyURL)
	if workerErr != nil {
		return nil, workerErr
	}

	return &Config{
		Pool:        pool,
		Client:      client,
		Logger:      logger,
		Port:        env.Port,
		Environment: env.Environment,
		ServiceName: env.ServiceName,
		Jwt:         jwt,
		TwoFactor:   twoFactor,
		RateLimiter: rateLimiter,
		Repository:  repository.New(pool),
		Domain:      NewDomain(env.Domain, env.API),
		Worker:      worker,
	}, nil
}

func (c *Config) Close() {
	if c.Pool != nil {
		c.Pool.Close()
	}
	if c.Client != nil {
		c.Client.Close()
	}
	if c.Worker != nil {
		if err := c.Worker.Close(); err != nil {
			c.Logger.Error("failed to close asynq worker client gracefully", "error", err)
		}
	}
}
