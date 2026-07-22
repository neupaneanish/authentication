package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/valkey-io/valkey-go/om"
	"github.com/valkey-io/valkey-go/valkeylimiter"

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
	id := uuid.NewString()

	token, tokenErr := s.cfg.Jwt.GenerateToken(userID, id)
	if tokenErr != nil {
		return nil, tokenErr
	}

	accessSession := &utils.LoginAccessSession{
		Key:    id,
		ExAt:   time.Now().Add(utils.AccessSessionExpiry),
		UserID: userID,
		Role:   role,
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

func (s *GatewayAuthenticationService) gatewayCheckPassword(
	ctx context.Context,
	serviceName string,
	rawPassword string,
	securityMethod enum.SecurityMethod,
) (string, error) {
	userSession, prefix, emailType, err := s.gatewayUserSessionLimiter(ctx, serviceName, securityMethod)
	if err != nil {
		return "", err
	}

	params := &repository.CredentialParams{UserID: userSession.UserID}
	row, rowErr := s.cfg.Repository.Credential(ctx, params)
	if rowErr != nil {
		if errors.Is(rowErr, pgx.ErrNoRows) {
			s.cfg.Logger.WarnContext(
				ctx,
				"No credentials found",
				"service",
				serviceName,
				"userID",
				userSession.UserID.String(),
			)
			// TODO: Delete Access and Refresh
			return "", errs.ErrSessionExpired
		}
		s.cfg.Logger.ErrorContext(ctx, "Postgres get", "service", serviceName, "error", rowErr)
		return "", errs.ErrInternalServer
	}

	if !utils.ComparePassword(row.Password, rawPassword) {
		s.cfg.Logger.WarnContext(
			ctx,
			"Invalid Password",
			"service",
			serviceName,
			"userID",
			userSession.UserID.String(),
		)
		return "", errs.ErrInvalidPassword
	}

	session := rand.Text()

	code, plain, codeErr := GenerateEmailCode(ctx, s.cfg.Logger)
	if codeErr != nil {
		return "", codeErr
	}

	data := &utils.GatewaySecuritySession{
		Key:     userSession.UserID.String(),
		ExAt:    time.Now().Add(utils.SessionExpiry),
		Code:    code,
		Email:   row.Email,
		Session: session,
	}

	if hSetErr := redis.HSet[utils.GatewaySecuritySession](
		ctx,
		prefix,
		data,
		s.cfg.Client,
	); hSetErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "Valkey HSet", "service", serviceName, "error", hSetErr)
		return "", errs.ErrInternalServer
	}

	var tErr error
	var t *asynq.Task

	if securityMethod == enum.DisableTwoFactor {
		t, tErr = task.SecurityNotification(emailType, row.Email)
	} else {
		t, tErr = task.AuthEmailTask(emailType, row.Email, plain)
	}

	_ = EmailEnqueue(ctx, t, tErr, serviceName, s.cfg.Logger, s.cfg.Worker) // Error already handled by EmailEnqueue

	return session, nil
}

func (s *GatewayAuthenticationService) gatewaySecuritySessionVerify(
	ctx context.Context,
	serviceName string,
	securityMethod enum.SecurityMethod,
	session string,
) (*utils.GatewaySecuritySession, error) {
	userSession, prefix, _, err := s.gatewayUserSessionLimiter(ctx, serviceName, securityMethod)
	if err != nil {
		return nil, err
	}
	data, dataErr := redis.HGet[utils.GatewaySecuritySession](ctx, prefix, userSession.UserID.String(), s.cfg.Client)
	if dataErr != nil {
		if om.IsRecordNotFound(dataErr) {
			s.cfg.Logger.WarnContext(ctx, "session expired", "service", serviceName)
			return nil, errs.ErrSessionExpired
		}
		s.cfg.Logger.ErrorContext(ctx, "valkey", "service", serviceName, "error", dataErr)

		return nil, errs.ErrInternalServer
	}

	if data.Session != session {
		s.cfg.Logger.WarnContext(ctx, "session expired", "service", serviceName)
		return nil, errs.ErrSessionExpired
	}
	return data, nil
}

func (s *GatewayAuthenticationService) deleteGatewaySecuritySession(
	ctx context.Context,
	prefix string,
	key string,
	serviceName string,
) {
	if hDeleteErr := redis.HDelete[utils.GatewaySecuritySession](
		ctx,
		prefix,
		key,
		s.cfg.Client,
	); hDeleteErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "Delete", "service", serviceName, "error", hDeleteErr)
	}
}

func (s *GatewayAuthenticationService) gatewayUserSessionLimiter(
	ctx context.Context,
	serviceName string,
	securityMethod enum.SecurityMethod,
) (*utils.UserSession, string, string, error) {
	userSession, userSessionErr := utils.GetUserSessionContext(ctx, serviceName, s.cfg.Logger)
	if userSessionErr != nil {
		return nil, "", "", userSessionErr
	}

	var result valkeylimiter.Result
	var resultErr error

	var prefix string
	var emailType string

	switch securityMethod {
	case enum.ChangePassword:
		result, resultErr = s.cfg.RateLimiter.PasswordWorkflow.Allow(ctx, userSession.UserID.String())
		prefix = utils.ChangePasswordSessionPrefix
		emailType = task.TypeChangePassword
	case enum.TwoFactor:
		result, resultErr = s.cfg.RateLimiter.TwoFactorWorkflow.Allow(ctx, userSession.UserID.String())
		prefix = utils.TwoFactorSessionPrefix
		emailType = task.TypeTwoFactor
	case enum.DisableTwoFactor:
		result, resultErr = s.cfg.RateLimiter.DeleteTwoFactorWorkflow.Allow(ctx, userSession.UserID.String())
		prefix = utils.DeleteTwoFactorSessionPrefix
		emailType = task.TypeDeleteTwoFactor
	default:
		s.cfg.Logger.ErrorContext(
			ctx,
			"Unmapped security method encountered",
			"service",
			serviceName,
			"method",
			securityMethod,
		)
		return nil, "", "", errs.ErrInternalServer
	}

	if limiterErr := LimiterCheck(
		ctx,
		&result,
		resultErr,
		serviceName,
		userSession.UserID.String(),
		s.cfg.Logger,
	); limiterErr != nil {
		return nil, "", "", limiterErr
	}
	return userSession, prefix, emailType, nil
}

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

	if reset {
		emailType = task.TypePasswordReset
	} else {
		emailType = task.TypeConfirmChangePassword
	}

	newHash, newHashErr := utils.CreatePassword(rawPassword)
	if newHashErr != nil {
		logger.ErrorContext(ctx, "password hash", "service", serviceName, "error", newHashErr)
		return errs.ErrInternalServer
	}

	credentialParams := &repository.CreateCredentialParams{UserID: userID, Password: newHash, CreatedBy: userID}

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
		return uuid.Nil, errs.ErrInternalServer
	}

	if len(row) == 0 {
		logger.WarnContext(ctx, "Recovery attempt with no codes in DB", "userID", userID)
		return uuid.Nil, errs.ErrSessionExpired
	}

	ok, id := twoFactor.ValidateRecoveryCode(code, row)
	if !ok {
		logger.WarnContext(
			ctx,
			"Invalid recovery code",
			"userID",
			userID.String(),
		)
		return uuid.Nil, errs.ErrInvalidCode
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
