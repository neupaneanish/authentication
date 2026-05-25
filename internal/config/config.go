package config

import (
	"context"
	"log/slog"
)

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

	return &Config{
		Pool:        pool,
		Client:      client,
		Logger:      logger,
		Port:        env.Port,
		Environment: env.Environment,
		ServiceName: env.ServiceName,
		Jwt:         jwt,
	}, nil
}

func (c *Config) Close() {
	if c.Pool != nil {
		c.Pool.Close()
	}
	if c.Client != nil {
		c.Client.Close()
	}
}
