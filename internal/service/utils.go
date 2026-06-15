package service

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeylimiter"
	"neupaneanish.com.np/api/internal/config"
	"neupaneanish.com.np/api/internal/enum"
	"neupaneanish.com.np/api/internal/errs"
	"neupaneanish.com.np/api/internal/redis"
	"neupaneanish.com.np/api/internal/task"
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
	account bool,
	email string,
	client valkey.Client,
	logger *slog.Logger,
	worker *asynq.Client,
) error {
	code, plain, err := GenerateEmailCode(ctx, logger)
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
		logger.ErrorContext(ctx, "Account verification ", "service", serviceName, "error", hSetErr, "method", method)
		return errs.ErrInternalServer
	}

	var taskType string

	if account {
		taskType = task.TypeAccountVerification
	} else {
		taskType = task.TypeEmailVerification
	}

	t, tErr := task.AuthEmailTask(taskType, email, plain)
	return EmailEnqueue(ctx, t, tErr, serviceName, logger, worker)
}

func EmailForgetPassword(
	ctx context.Context,
	session string,
	userID string,
	email string,
	serviceName string,
	client valkey.Client,
	logger *slog.Logger,
	worker *asynq.Client,
) error {
	code, plain, codeErr := GenerateEmailCode(ctx, logger)
	if codeErr != nil {
		return codeErr
	}

	data := &utils.ForgetPasswordSession{
		Key:    session,
		ExAt:   time.Now().Add(utils.SessionExpiry),
		UserID: userID,
		Code:   code,
		Email:  email,
	}

	hSetErr := redis.HSet[utils.ForgetPasswordSession](ctx, utils.ForgetPasswordSessionPrefix, data, client)
	if hSetErr != nil {
		logger.ErrorContext(ctx, "Valkey Access HSet", "service", serviceName, "error", hSetErr)
		return errs.ErrInternalServer
	}

	t, tErr := task.AuthEmailTask(task.TypeForgetPassword, email, plain)
	return EmailEnqueue(ctx, t, tErr, serviceName, logger, worker)
}

func EmailEnqueue(
	ctx context.Context,
	t *asynq.Task,
	tErr error,
	serviceName string,
	logger *slog.Logger,
	worker *asynq.Client,
) error {
	if tErr != nil {
		logger.ErrorContext(ctx, "New email task failed", "service", serviceName, "error", tErr)
		return errs.ErrInternalServer
	}

	info, workerErr := worker.Enqueue(t)
	if workerErr != nil {
		logger.ErrorContext(ctx, "Failed to enqueue email task", "service", serviceName, "error", workerErr)
		return errs.ErrInternalServer
	}

	logger.InfoContext(
		ctx,
		"Successfully enqueue task",
		"service",
		serviceName,
		"task_id",
		info.ID,
		"queue",
		info.Queue,
		"type",
		info.Type,
	)

	return nil
}
