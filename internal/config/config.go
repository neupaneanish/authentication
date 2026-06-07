package config

import (
	"context"
	"log/slog"

	"neupaneanish.com.np/api/internal/repository"
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

	twoFactor, twoFactorErr := NewTwoFactor(env.TwoFactorKey, env.Issuer)
	if twoFactorErr != nil {
		return nil, twoFactorErr
	}

	rateLimiter, rateLimiterErr := NewLimiter(client)
	if rateLimiterErr != nil {
		return nil, rateLimiterErr
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
		Domain:      env.Domain,
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
