package config

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/valkey-io/valkey-go"

	"neupaneanish.com.np/authentication/internal/repository"
)

type Config struct {
	Pool          *pgxpool.Pool
	Client        valkey.Client
	Logger        *slog.Logger
	Jwt           *JWT
	TwoFactor     *TwoFactor
	RateLimiter   *RateLimiter
	Repository    repository.Querier
	EmailVerifier *EmailVerifier
	Redpanda      *kgo.Client
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

	jwt, jwtErr := NewJWT(ctx, env.JWTKey, env.Issuer, logger)
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

	emailVerifier := NewEmailVerifier(env.AllowFree, env.AllowRole)

	redpanda, redpandaErr := NewRedpanda(ctx, env.RedpandaURL, env.RedpandaGroup)
	if redpandaErr != nil {
		return nil, redpandaErr
	}

	return &Config{
		Pool:          pool,
		Client:        client,
		Logger:        logger,
		Jwt:           jwt,
		TwoFactor:     twoFactor,
		RateLimiter:   rateLimiter,
		Repository:    repository.New(pool),
		EmailVerifier: emailVerifier,
		Redpanda:      redpanda,
	}, nil
}

func (c *Config) Close(ctx context.Context) {
	if c.Pool != nil {
		c.Pool.Close()
	}
	if c.Client != nil {
		c.Client.Close()
	}
	if c.Redpanda != nil {
		if err := c.Redpanda.Flush(ctx); err != nil {
			c.Logger.ErrorContext(ctx, "failed to flush redpanda", "error", err)
		}
		c.Redpanda.Close()
	}
}
