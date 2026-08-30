package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"uuid"

	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/valkey-io/valkey-go/valkeylimiter"

	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"

	"neupaneanish.com.np/authentication/internal/config"
	"neupaneanish.com.np/authentication/internal/enum"
	"neupaneanish.com.np/authentication/internal/errs"
	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/internal/repository"
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
	id := uuid.NewV7().String()

	token, tokenErr := s.cfg.Jwt.GenerateToken(userID, id)
	if tokenErr != nil {
		return nil, tokenErr
	}

	accessSession := &utils.LoginAccessSession{
		Key:     id,
		ExAt:    time.Now().Add(utils.AccessSessionExpiry),
		UserID:  userID,
		Role:    role,
		Refresh: token.Refresh,
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

	if err := redis.SAdd(ctx, utils.UserSessionPrefix+userID, id, utils.AccessSessionExpiry, s.cfg.Client); err != nil {
		s.cfg.Logger.ErrorContext(ctx, "Valkey SAdd access", "service", serviceName, "error", err)
		return nil, errs.ErrInternalServer
	}

	if err := redis.SAdd(
		ctx,
		utils.UserSessionPrefix+userID,
		token.Refresh,
		utils.RefreshSessionExpiry,
		s.cfg.Client,
	); err != nil {
		s.cfg.Logger.ErrorContext(ctx, "Valkey SAdd refresh", "service", serviceName, "error", err)
		return nil, errs.ErrInternalServer
	}

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

const (
	UsersEmailKey = "users_email_key"
	UsersPhoneKey = "users_phone_key"
)

func ChangeResetPassword(
	ctx context.Context,
	pool *pgxpool.Pool,
	repo repository.Querier,
	userID uuid.UUID,
	serviceName string,
	logger *slog.Logger,
	rawPassword string,
	email string,
	reset bool,
	worker *asynq.Client,
) error {
	params := &repository.CredentialsParams{UserID: userID, HistoryLimit: utils.CredentialsHistoryLimit}

	passwords, passwordsErr := repo.Credentials(ctx, params)
	if passwordsErr != nil {
		logger.ErrorContext(ctx, "database", "service", serviceName, "error", passwordsErr)
		return errs.ErrInternalServer
	}

	if len(passwords) == 0 {
		logger.WarnContext(ctx, "notfound", "service", serviceName)
		return errs.ErrSessionExpired
	}

	for _, hash := range passwords {
		if utils.ComparePassword(hash, rawPassword) {
			logger.WarnContext(ctx, "Previous password", "service", serviceName, "userID", userID)
			return errs.ErrPreviousPassword
		}
	}

	var emailType string
	var createdBy uuid.UUID

	if reset {
		emailType = task.TypePasswordReset
		createdBy = uuid.Nil()
	} else {
		emailType = task.TypeConfirmChangePassword
		createdBy = userID
	}

	newHash, newHashErr := utils.CreatePassword(rawPassword)
	if newHashErr != nil {
		logger.ErrorContext(ctx, "password hash", "service", serviceName, "error", newHashErr)
		return errs.ErrInternalServer
	}

	credentialParams := &repository.CreateCredentialParams{UserID: userID, Password: newHash, CreatedBy: createdBy}

	tx, txErr := pool.Begin(ctx)
	if txErr != nil {
		logger.ErrorContext(ctx, "transactions", "service", serviceName, "error", txErr)
		return errs.ErrInternalServer
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	qtx := repository.New(tx)

	tag, tagErr := qtx.CreateCredential(ctx, credentialParams)
	if err := AffectedRowCheck(ctx, tag, tagErr, "create credentials", serviceName, 1, logger); err != nil {
		return err
	}

	if txCommitErr := tx.Commit(ctx); txCommitErr != nil {
		logger.ErrorContext(ctx, "commit", "service", serviceName, "error", txCommitErr)
		return errs.ErrInternalServer
	}

	t, tErr := task.SecurityNotification(emailType, email)
	_ = EmailEnqueue(ctx, t, tErr, serviceName, logger, worker) // Error already handled by EmailEnqueue

	return nil
}

func ValidateTotpCode(
	ctx context.Context,
	userID uuid.UUID,
	repo repository.Querier,
	code string,
	serviceName string,
	twoFactor *config.TwoFactor,
	logger *slog.Logger,
) error {
	params := &repository.TwoFactorSecretParams{UserID: userID}
	row, rowErr := repo.TwoFactorSecret(ctx, params)
	if rowErr != nil {
		if errors.Is(rowErr, pgx.ErrNoRows) {
			logger.WarnContext(ctx, "data not found", "service", serviceName, "userID", userID.String())
			return errs.ErrSessionExpired
		}
		logger.ErrorContext(ctx, "secret database", "service", serviceName, "error", rowErr)
		return errs.ErrInternalServer
	}

	ok, validateErr := twoFactor.Validate(code, row)
	if validateErr != nil {
		logger.ErrorContext(ctx, "validation", "service", serviceName, "error", validateErr)
		return errs.ErrInternalServer
	}
	if !ok {
		logger.WarnContext(ctx, "code error", "service", serviceName, "userID", userID.String())
		return errs.ErrInvalidCode
	}
	return nil
}

func ValidateRecoveryCode(
	ctx context.Context,
	userID uuid.UUID,
	repo repository.Querier,
	code string,
	serviceName string,
	twoFactor *config.TwoFactor,
	logger *slog.Logger,
) (uuid.UUID, error) {
	params := &repository.RecoveryCodesParams{UserID: userID}
	row, rowErr := repo.RecoveryCodes(ctx, params)
	if rowErr != nil {
		logger.ErrorContext(ctx, serviceName+" recovery code database", "error", rowErr)
		return uuid.Nil(), errs.ErrInternalServer
	}

	if len(row) == 0 {
		logger.WarnContext(ctx, "Recovery attempt with no codes in DB", "userID", userID)
		return uuid.Nil(), errs.ErrSessionExpired
	}

	ok, id := twoFactor.ValidateRecoveryCode(code, row)
	if !ok {
		logger.WarnContext(
			ctx,
			"Invalid recovery code",
			"userID",
			userID.String(),
		)
		return uuid.Nil(), errs.ErrInvalidCode
	}
	return id, nil
}

func AffectedRowCheck(
	ctx context.Context,
	tag pgconn.CommandTag,
	tagErr error,
	msg string,
	serviceName string,
	count int64,
	logger *slog.Logger,
) error {
	if tagErr != nil {
		logger.ErrorContext(ctx, msg+" execution failure", "service", serviceName, "error", tagErr)
		return errs.ErrInternalServer
	}

	if tag.RowsAffected() != count {
		logger.WarnContext(ctx, msg+" rows mismatch",
			"service", serviceName,
			"expected", count,
			"actual", tag.RowsAffected(),
		)
		return errs.ErrInternalServer
	}
	return nil
}

func (s *GatewayAuthenticationService) logoutAll(ctx context.Context, userID, serviceName string) error {
	keys, keysErr := redis.SMembers(ctx, utils.UserSessionPrefix+userID, s.cfg.Client)
	if keysErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "Valkey SMembers failed", "service", serviceName, "error", keysErr)
		return errs.ErrInternalServer
	}

	for _, key := range keys {
		_ = redis.HDelete[utils.LoginAccessSession](ctx, utils.LoginAccessSessionPrefix, key, s.cfg.Client)
		_ = redis.HDelete[utils.LoginRefreshSession](ctx, utils.LoginRefreshSessionPrefix, key, s.cfg.Client)
	}

	if err := redis.Del(ctx, utils.UserSessionPrefix+userID, s.cfg.Client); err != nil {
		s.cfg.Logger.ErrorContext(ctx, "Valkey Del set failed", "service", serviceName, "error", err)
		return errs.ErrInternalServer
	}

	return nil
}

func (s *ExternalAuthenticationService) verification(
	ctx context.Context,
	userID uuid.UUID,
	role enum.UserRole,
	email,
	session,
	serviceName string,
	method enum.Method,
	verificationMethod enum.VerificationMethod,
	enabledTwoFactor bool,
) error {
	code, format, codeErr := GenerateEmailCode(ctx, s.cfg.Logger)
	if codeErr != nil {
		return codeErr
	}
	var taskType string

	switch verificationMethod {
	case enum.VerificationMethodAccount:
		taskType = task.TypeAccountVerification
	case enum.VerificationMethodEmail:
		taskType = task.TypeEmailVerification
	case enum.VerificationMethodReset:
		taskType = task.TypePasswordReset
	case enum.VerificationMethodTwoFactor:
		taskType = task.TypeEnableTwoFactor // Two Factor doesn't send email, its only placeholder
	default:
		s.cfg.Logger.ErrorContext(
			ctx,
			"Invalid verification method",
			"service",
			serviceName,
			"method",
			verificationMethod,
		)
		return errs.ErrSessionExpired
	}

	data := &utils.VerificationSession{
		Key:                session,
		ExAt:               time.Now().Add(utils.SessionExpiry),
		UserID:             userID.String(),
		Role:               string(role),
		Method:             string(method),
		VerificationMethod: string(verificationMethod),
		Code:               code,
		Email:              email,
		EnabledTwoFactor:   enabledTwoFactor,
	}

	if err := redis.HSet[utils.VerificationSession](
		ctx,
		utils.VerificationSessionPrefix,
		data,
		s.cfg.Client,
	); err != nil {
		s.cfg.Logger.ErrorContext(ctx, "Valkey Verification HSet", "service", serviceName, "error", err)
		return errs.ErrInternalServer
	}

	if verificationMethod == enum.VerificationMethodTwoFactor {
		return nil
	}

	t, tErr := task.AuthEmailTask(taskType, email, format)
	return EmailEnqueue(ctx, t, tErr, serviceName, s.cfg.Logger, s.cfg.Worker)
}

func externalVerification(
	session string,
	method externalAuthenticationv1.VerificationMethod,
) *externalAuthenticationv1.VerificationSession {
	return &externalAuthenticationv1.VerificationSession{
		Session: session,
		Method:  method,
	}
}
