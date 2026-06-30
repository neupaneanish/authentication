package service

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/valkey-io/valkey-go/valkeylimiter"
	"neupaneanish.com.np/authentication/internal/config"
	"neupaneanish.com.np/authentication/internal/enum"
	"neupaneanish.com.np/authentication/internal/errs"
	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/internal/task"
	"neupaneanish.com.np/authentication/internal/utils"
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

func (s *ExternalAuthenticationService) login(
	ctx context.Context,
	userID string,
	role string,
	serviceName string,
) (*config.GenerateJwt, error) {
	id := uuid.NewString()

	token, tokenErr := s.cfg.Jwt.GenerateToken(userID, role, id)
	if tokenErr != nil {
		return nil, tokenErr
	}

	accessSession := &utils.LoginAccessSession{
		Key:    id,
		ExAt:   time.Now().Add(utils.AccessSessionExpiry),
		UserID: userID,
	}

	hSetErr := redis.HSet[utils.LoginAccessSession](ctx, utils.LoginAccessSessionPrefix, accessSession, s.cfg.Client)
	if hSetErr != nil {
		s.cfg.Logger.ErrorContext(ctx, serviceName+" Valkey Access HSet", "error", hSetErr)
		return nil, errs.ErrInternalServer
	}

	refreshSession := &utils.LoginRefreshSession{
		Key:    token.Refresh,
		ExAt:   time.Now().Add(utils.RefreshSessionExpiry),
		UserID: userID,
		Role:   role,
		ID:     id,
	}

	rHSetErr := redis.HSet[utils.LoginRefreshSession](
		ctx,
		utils.LoginRefreshSessionPrefix,
		refreshSession,
		s.cfg.Client,
	)
	if rHSetErr != nil {
		s.cfg.Logger.ErrorContext(ctx, serviceName+" Valkey Refresh HSet", "error", rHSetErr)
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

func (s *ExternalAuthenticationService) emailVerification(
	ctx context.Context,
	serviceName string,
	method enum.Method,
	session string,
	userID string,
	role string,
	twoFactor bool,
	account bool,
	email string,
) error {
	code, plain, err := GenerateEmailCode(ctx, s.cfg.Logger)
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
		Account:   account,
		Email:     email,
	}

	hSetErr := redis.HSet[utils.AccountVerificationSession](
		ctx,
		utils.AccountVerificationSessionPrefix,
		data,
		s.cfg.Client,
	)
	if hSetErr != nil {
		s.cfg.Logger.ErrorContext(
			ctx,
			"Account verification ",
			"service",
			serviceName,
			"error",
			hSetErr,
			"method",
			method,
		)
		return errs.ErrInternalServer
	}

	var taskType string

	if account {
		taskType = task.TypeAccountVerification
	} else {
		taskType = task.TypeEmailVerification
	}

	t, tErr := task.AuthEmailTask(taskType, email, plain)
	return EmailEnqueue(ctx, t, tErr, serviceName, s.cfg.Logger, s.cfg.Worker)
}

func (s *ExternalAuthenticationService) emailForgetPassword(
	ctx context.Context,
	session string,
	userID string,
	email string,
	serviceName string,
) error {
	code, plain, codeErr := GenerateEmailCode(ctx, s.cfg.Logger)
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

	hSetErr := redis.HSet[utils.ForgetPasswordSession](ctx, utils.ForgetPasswordSessionPrefix, data, s.cfg.Client)
	if hSetErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "Valkey Access HSet", "service", serviceName, "error", hSetErr)
		return errs.ErrInternalServer
	}

	t, tErr := task.AuthEmailTask(task.TypeForgetPassword, email, plain)
	return EmailEnqueue(ctx, t, tErr, serviceName, s.cfg.Logger, s.cfg.Worker)
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

func (s *ExternalAuthenticationService) twoFactorSession(
	ctx context.Context,
	session string,
	userID string,
	role string,
	serviceName string,
) error {
	tfSession := &utils.LoginTwoFactorSession{
		Key:    session,
		ExAt:   time.Now().Add(utils.SessionExpiry),
		UserID: userID,
		Role:   role,
	}
	hSetErr := redis.HSet[utils.LoginTwoFactorSession](
		ctx,
		utils.LoginTwoFactorSessionPrefix,
		tfSession,
		s.cfg.Client,
	)
	if hSetErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "Valkey Two Factor HSet", "service", serviceName, "error", hSetErr)
		return errs.ErrInternalServer
	}
	return nil
}

const (
	UsersEmailKey = "users_email_key"
	UsersPhoneKey = "users_phone_key"
)

func (s *GatewayAuthenticationService) gatewayAuthenticationSecurityWorkflow(
	ctx context.Context,
	userID string,
	serviceName string,
	password bool,
) error {
	var result valkeylimiter.Result
	var resultErr error
	if password {
		result, resultErr = s.cfg.RateLimiter.PasswordWorkflow.Allow(ctx, userID)
	} else {
		result, resultErr = s.cfg.RateLimiter.TwoFactorWorkflow.Allow(ctx, userID)
	}

	if limiterErr := LimiterCheck(
		ctx,
		&result,
		resultErr,
		serviceName,
		userID,
		s.cfg.Logger,
	); limiterErr != nil {
		return limiterErr
	}
	return nil
}

func (s *GatewayAuthenticationService) gatewayAuthenticationSecurityWorkflowCache(
	ctx context.Context,
	userID string,
	email string,
	session string,
	serviceName string,
	password bool,
) error {
	code, plain, codeErr := GenerateEmailCode(ctx, s.cfg.Logger)
	if codeErr != nil {
		return codeErr
	}

	data := &utils.GatewaySecuritySession{
		Key:     userID,
		ExAt:    time.Now().Add(utils.SessionExpiry),
		Code:    code,
		Email:   email,
		Session: session,
	}

	var prefix string
	var emailType string

	if password {
		prefix = utils.ChangePasswordSessionPrefix
		emailType = task.TypeChangePassword
	} else {
		prefix = utils.TwoFactorSessionPrefix
		emailType = task.TypeTwoFactor
	}

	if hSetErr := redis.HSet[utils.GatewaySecuritySession](
		ctx,
		prefix,
		data,
		s.cfg.Client,
	); hSetErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "Valkey HSet", "service", serviceName, "error", hSetErr)
		return errs.ErrInternalServer
	}

	t, tErr := task.AuthEmailTask(emailType, email, plain)
	if emailEnqueueErr := EmailEnqueue(ctx, t, tErr, serviceName, s.cfg.Logger, s.cfg.Worker); emailEnqueueErr != nil {
		return emailEnqueueErr
	}
	return nil
}
