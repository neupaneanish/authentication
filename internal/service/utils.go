package service

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeylimiter"
	"neupaneanish.com.np/api/internal/config"
	"neupaneanish.com.np/api/internal/enum"
	"neupaneanish.com.np/api/internal/errs"
	"neupaneanish.com.np/api/internal/redis"
	"neupaneanish.com.np/api/internal/utils"
)

func LimiterCheck(
	ctx context.Context,
	result *valkeylimiter.Result,
	resultErr error,
	serviceName string,
	value string,
	logger *slog.Logger,
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
	userID string,
	role string,
	serviceName string,
	jwt *config.JWT,
	client valkey.Client,
	logger *slog.Logger,
) (*config.GenerateJwt, error) {
	id := uuid.NewString()

	token, tokenErr := jwt.GenerateToken(userID, role, id)
	if tokenErr != nil {
		return nil, errs.ErrInternalServer
	}

	accessSession := &utils.LoginAccessSession{
		Key:    id,
		ExAt:   time.Now().Add(utils.AccessSessionExpiry),
		UserID: userID,
	}

	hSetErr := redis.HSet[utils.LoginAccessSession](ctx, utils.LoginAccessSessionPrefix, accessSession, client)
	if hSetErr != nil {
		logger.ErrorContext(ctx, serviceName+" Valkey Access HSet", "error", hSetErr)
		return nil, errs.ErrInternalServer
	}

	refreshSession := &utils.LoginRefreshSession{
		Key:    token.Refresh,
		ExAt:   time.Now().Add(utils.RefreshSessionExpiry),
		UserID: userID,
		Role:   role,
		ID:     id,
	}

	rHSetErr := redis.HSet[utils.LoginRefreshSession](ctx, utils.LoginRefreshSessionPrefix, refreshSession, client)
	if rHSetErr != nil {
		logger.ErrorContext(ctx, serviceName+" Valkey Refresh HSet", "error", rHSetErr)
		return nil, errs.ErrInternalServer
	}

	// TODO: Store in valkey for reverse loogup (Access / Refresh)

	return token, nil
}

func GenerateEmailCode(ctx context.Context, logger *slog.Logger) (string, string, error) {
	codeByte := make([]byte, utils.EmailCodeBytes)
	if _, err := rand.Read(codeByte); err != nil {
		logger.ErrorContext(ctx, "generate Email code", "error", err)
		return "", "", errs.ErrInternalServer
	}

	code := fmt.Sprintf("%X", codeByte)
	format := fmt.Sprintf("%s-%s", code[0:4], code[4:8])

	return code, format, nil
}

func EmailVerification(
	ctx context.Context,
	serviceName string,
	method enum.Method,
	session string,
	userID string,
	role string,
	twoFactor bool,
	client valkey.Client,
	logger *slog.Logger,
) error {
	code, _, err := GenerateEmailCode(ctx, logger)
	if err != nil {
		return err
	}

	data := &utils.AccountVerificationSession{
		Key:       session,
		ExAt:      time.Now().Add(utils.SessionExpiry),
		UserID:    userID,
		Role:      role,
		Method:    string(method),
		Code:      code,
		TwoFactor: twoFactor,
	}

	hSetErr := redis.HSet[utils.AccountVerificationSession](ctx, utils.AccountVerificationSessionPrefix, data, client)
	if hSetErr != nil {
		logger.ErrorContext(ctx, serviceName+" account verification ", "error", hSetErr, "method", method)
		return errs.ErrInternalServer
	}

	// TODO: Send Email Verification
	return nil
}
