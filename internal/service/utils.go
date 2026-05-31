package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/valkey-io/valkey-go/valkeylimiter"
	"neupaneanish.com.np/api/internal/config"
	"neupaneanish.com.np/api/internal/errs"
	"neupaneanish.com.np/api/internal/redis"
)

func (s *AuthService) limiterCheck(
	ctx context.Context,
	result *valkeylimiter.Result,
	resultErr error,
	serviceName string,
	value string,
) error {
	if resultErr != nil {
		s.cfg.Logger.ErrorContext(ctx, serviceName+" limiter", "error", resultErr)
		return errs.ErrInternalServer
	}

	if !result.Allowed {
		s.cfg.Logger.WarnContext(ctx, serviceName+" limit exceed", "remaining", result.Remaining, "data", value)
		return errs.ErrTooManyRequest
	}
	return nil
}

func (s *AuthService) login(
	ctx context.Context,
	userID string,
	role string,
	serviceName string,
) (*config.GenerateJwt, error) {
	id := uuid.NewString()

	token, tokenErr := s.cfg.Jwt.GenerateToken(userID, role, id)
	if tokenErr != nil {
		return nil, errs.ErrInternalServer
	}

	accessSession := &LoginAccessSession{
		Key:    id,
		ExAt:   time.Now().Add(AccessSessionExpiry),
		UserID: userID,
	}

	hSetErr := redis.HSet[LoginAccessSession](ctx, LoginAccessSessionPrefix, accessSession, s.cfg.Client)
	if hSetErr != nil {
		s.cfg.Logger.ErrorContext(ctx, serviceName+" Valkey Access HSet", "error", hSetErr)
		return nil, errs.ErrInternalServer
	}

	refreshSession := &LoginRefreshSession{
		Key:    token.Refresh,
		ExAt:   time.Now().Add(RefreshSessionExpiry),
		UserID: userID,
		Role:   role,
		ID:     id,
	}
	rHSetErr := redis.HSet[LoginRefreshSession](ctx, LoginRefreshSessionPrefix, refreshSession, s.cfg.Client)
	if rHSetErr != nil {
		s.cfg.Logger.ErrorContext(ctx, serviceName+" Valkey Refresh HSet", "error", rHSetErr)
		return nil, errs.ErrInternalServer
	}

	// TODO: Store in valkey for reverse loogup (Access / Refresh)

	return token, nil
}
