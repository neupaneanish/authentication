package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeylimiter"
	"golang.org/x/sync/errgroup"

	"neupaneanish.com.np/authentication/internal/redpanda"

	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"

	"neupaneanish.com.np/authentication/internal/config"
	"neupaneanish.com.np/authentication/internal/enum"
	"neupaneanish.com.np/authentication/internal/errs"
	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/internal/repository"
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

const (
	UsersEmailKey = "users_email_key"
	UsersPhoneKey = "users_phone_key"
)

func ChangeResetPassword(
	ctx context.Context,
	userID uuid.UUID,
	username, serviceName, rawPassword, email string,
	reset bool,
	pool *pgxpool.Pool,
	repo repository.Querier,
	client *kgo.Client,
	logger *slog.Logger,
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

	g, gCtx := errgroup.WithContext(ctx)

	for _, hash := range passwords {
		g.Go(func() error {
			if err := gCtx.Err(); err != nil {
				return err
			}

			if utils.ComparePassword(hash, rawPassword) {
				logger.WarnContext(ctx, "Previous password", "service", serviceName, "userID", userID)
				return errs.ErrPreviousPassword
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}

	var emailTemplate string
	var method string
	var createdBy uuid.UUID

	if reset {
		emailTemplate = utils.EmailTemplatePasswordReset
		method = utils.DatabaseMethodReset
		createdBy = uuid.Nil()
	} else {
		emailTemplate = utils.EmailTemplateConfirmChangePassword
		method = utils.DatabaseMethodUpdate
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

	if err := qtx.CreateCredential(ctx, credentialParams); err != nil {
		logger.ErrorContext(ctx, "Failed to create credential", "service", serviceName, "error", err)
		return errs.ErrInternalServer
	}

	if txCommitErr := tx.Commit(ctx); txCommitErr != nil {
		logger.ErrorContext(ctx, "commit", "service", serviceName, "error", txCommitErr)
		return errs.ErrInternalServer
	}

	redpanda.SecurityEmailProduce(ctx, userID, email, emailTemplate, serviceName, client, logger)
	redpanda.RootNotificationProduce(
		ctx,
		userID,
		userID,
		username,
		utils.DatabaseTableCredential,
		method,
		serviceName,
		client,
		logger,
	)
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
	affected int64,
	affectedErr error,
	msg string,
	serviceName string,
	count int64,
	logger *slog.Logger,
) error {
	if affectedErr != nil {
		logger.ErrorContext(ctx, msg+" execution failure", "service", serviceName, "error", affectedErr)
		return errs.ErrInternalServer
	}

	if affected != count {
		logger.WarnContext(ctx, msg+" rows mismatch",
			"service", serviceName,
			"expected", count,
			"actual", affected,
		)
		return errs.ErrConflict
	}
	return nil
}

func LogoutAll(ctx context.Context, userID, serviceName string, client valkey.Client, logger *slog.Logger) {
	keys, keysErr := redis.SMembers(ctx, utils.UserSessionPrefix+userID, client)
	if keysErr != nil {
		logger.ErrorContext(ctx, "Valkey SMembers failed", "service", serviceName, "error", keysErr)
		return
	}

	for _, key := range keys {
		_ = redis.HDelete[utils.LoginAccessSession](ctx, utils.LoginAccessSessionPrefix, key, client)
		_ = redis.HDelete[utils.LoginRefreshSession](ctx, utils.LoginRefreshSessionPrefix, key, client)
	}

	if err := redis.Del(ctx, utils.UserSessionPrefix+userID, client); err != nil {
		logger.ErrorContext(ctx, "Valkey Del set failed", "service", serviceName, "error", err)
		return
	}
}

func (s *ExternalAuthenticationService) verification(
	ctx context.Context,
	userID uuid.UUID,
	role enum.UserRole,
	username,
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
	var emailTemplate string

	switch verificationMethod {
	case enum.VerificationMethodAccount:
		emailTemplate = utils.EmailTemplateAccountVerification
	case enum.VerificationMethodEmail:
		emailTemplate = utils.EmailTemplateEmailVerification
	case enum.VerificationMethodReset:
		emailTemplate = utils.EmailTemplateForgetPassword
	case enum.VerificationMethodTwoFactor:
		emailTemplate = utils.EmailTemplateEnableTwoFactor // Two Factor doesn't send email, its only placeholder
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
		Username:           username,
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

	if verificationMethod != enum.VerificationMethodTwoFactor {
		redpanda.AuthEmailProduce(ctx, userID, format, email, emailTemplate, serviceName, s.cfg.Redpanda, s.cfg.Logger)
	}

	return nil
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

func (s *RootAuthenticationService) updateRoleStatusUsername(
	ctx context.Context,
	id, value, serviceName, method string,
	updatedAt time.Time,
) error {
	userSession := utils.UserSessionContext(ctx)

	idx, idxErr := utils.ParsedUUID(ctx, id, serviceName, s.cfg.Logger)
	if idxErr != nil {
		return idxErr
	}

	if idx == userSession.UserID {
		s.cfg.Logger.WarnContext(ctx, "Attempted self update", "service", serviceName)
		return errs.ErrSelfUpdate
	}

	var affected int64
	var affectedErr error

	switch method {
	case "status":
		status := enum.UserStatus(value)
		if !status.Valid() {
			s.cfg.Logger.WarnContext(ctx, "Invalid Status", "service", serviceName)
			return errs.ErrInvalidStatus
		}
		params := &repository.UpdateStatusParams{
			Status:    status,
			UpdatedBy: userSession.UserID,
			ID:        idx,
			UpdatedAt: updatedAt,
		}
		affected, affectedErr = s.cfg.Repository.UpdateStatus(ctx, params)
	case "role":
		role := enum.UserRole(value)
		if !role.Valid() {
			s.cfg.Logger.WarnContext(ctx, "Invalid Role", "service", serviceName)
			return errs.ErrInvalidRole
		}
		params := &repository.UpdateRoleParams{
			Role:      role,
			UpdatedBy: userSession.UserID,
			ID:        idx,
			UpdatedAt: updatedAt,
		}
		affected, affectedErr = s.cfg.Repository.UpdateRole(ctx, params)
	default:
		s.cfg.Logger.WarnContext(ctx, "Invalid method", "service", serviceName, "method", method)
		return errs.ErrInternalServer
	}

	if err := AffectedRowCheck(ctx, affected, affectedErr, "update "+method, serviceName, 1, s.cfg.Logger); err != nil {
		return err
	}

	LogoutAll(ctx, id, serviceName, s.cfg.Client, s.cfg.Logger)
	return nil
}

func setUsername(ctx context.Context, userID, username, service string, client valkey.Client, logger *slog.Logger) {
	key := fmt.Sprintf("user:username:%s", userID)
	cmd := client.B().Set().Key(key).Value(username).Build()
	if err := client.Do(ctx, cmd).Error(); err != nil {
		logger.ErrorContext(ctx, "Failed to update username", "service", service, "username", username, "error", err)
	}
}
