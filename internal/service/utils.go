package service

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeylimiter"
	"neupaneanish.com.np/api/internal/config"
	"neupaneanish.com.np/api/internal/errs"
	"neupaneanish.com.np/api/internal/redis"
)

func limiterCheck(
	ctx context.Context,
	result *valkeylimiter.Result,
	resultErr error,
	serviceName string,
	logger *slog.Logger,
	value string,
) error {
	if resultErr != nil {
		logger.ErrorContext(ctx, serviceName+" limiter", "error", resultErr)
		return errs.ErrInternalServer
	}

	if !result.Allowed {
		logger.WarnContext(ctx, serviceName+" limit exceed", "remaining", result.Remaining, "data", value)
		return errs.ErrTooManyRequest
	}
	return nil
}

func login(
	ctx context.Context,
	jwt *config.JWT,
	userID string,
	role string,
	serviceName string,
	logger *slog.Logger,
	client valkey.Client,
) (*config.GenerateJwt, error) {
	id := uuid.NewString()

	token, tokenErr := jwt.GenerateToken(userID, role, id)
	if tokenErr != nil {
		return nil, errs.ErrInternalServer
	}

	accessSession := &LoginAccessSession{
		Key:    id,
		ExAt:   time.Now().Add(AccessSessionExpiry),
		UserID: userID,
	}

	hSetErr := redis.HSet[LoginAccessSession](ctx, LoginAccessSessionPrefix, accessSession, client)
	if hSetErr != nil {
		logger.ErrorContext(ctx, serviceName+" Valkey Access HSet", "error", hSetErr)
		return nil, errs.ErrInternalServer
	}

	refreshSession := &LoginRefreshSession{
		Key:    token.Refresh,
		ExAt:   time.Now().Add(RefreshSessionExpiry),
		UserID: userID,
		Role:   role,
		ID:     id,
	}
	rHSetErr := redis.HSet[LoginRefreshSession](ctx, LoginRefreshSessionPrefix, refreshSession, client)
	if rHSetErr != nil {
		logger.ErrorContext(ctx, serviceName+" Valkey Refresh HSet", "error", rHSetErr)
		return nil, errs.ErrInternalServer
	}

	// TODO: Store in valkey for reverse loogup (Access / Refresh)

	return token, nil
}
