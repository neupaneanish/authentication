package service

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/valkey-io/valkey-go/om"
	"google.golang.org/protobuf/types/known/timestamppb"
	"neupaneanish.com.np/api/internal/errs"
	authv1 "neupaneanish.com.np/api/internal/protobuf/auth/v1"
	"neupaneanish.com.np/api/internal/redis"
	"neupaneanish.com.np/api/internal/repository"
)

type validateTwoFactor struct {
	code        string
	userID      uuid.UUID
	session     string
	role        string
	serviceName string
}

type loginTF struct {
	userID      uuid.UUID
	session     string
	role        string
	id          uuid.UUID
	updatedAt   time.Time
	serviceName string
	totp        bool
}

func (s *AuthService) LoginTwoFactor(
	ctx context.Context,
	req *authv1.LoginTwoFactorRequest,
) (*authv1.LoginTwoFactorResponse, error) {
	serviceName := "LoginTwoFactor"
	session := req.GetSession()

	resultSession, resultSessionErr := s.cfg.RateLimiter.LoginTwoFactor.Allow(ctx, session)
	limiterSessionErr := s.limiterCheck(ctx, &resultSession, resultSessionErr, serviceName, session)
	if limiterSessionErr != nil {
		return nil, limiterSessionErr
	}

	data, dataErr := redis.HGet[LoginTwoFactorSession](ctx, LoginTwoFactorSessionPrefix, session, s.cfg.Client)
	if dataErr != nil {
		if om.IsRecordNotFound(dataErr) {
			s.cfg.Logger.WarnContext(ctx, serviceName+" not found", "session", session)
			return nil, errs.ErrSessionExpired
		}
		s.cfg.Logger.ErrorContext(ctx, serviceName+" valkey", "error", dataErr)
		return nil, errs.ErrInternalServer
	}

	result, resultErr := s.cfg.RateLimiter.LoginTwoFactor.Allow(ctx, data.UserID)
	limiterErr := s.limiterCheck(ctx, &result, resultErr, serviceName, data.UserID)
	if limiterErr != nil {
		return nil, limiterErr
	}

	userID := uuid.MustParse(data.UserID)

	switch m := req.GetCode().(type) {
	case *authv1.LoginTwoFactorRequest_Totp:
		validate := &validateTwoFactor{
			code:        m.Totp,
			userID:      userID,
			session:     session,
			role:        data.Role,
			serviceName: serviceName,
		}
		return s.validTotpCode(ctx, validate)
	case *authv1.LoginTwoFactorRequest_Recovery:
		validate := &validateTwoFactor{
			code:        m.Recovery,
			userID:      userID,
			session:     session,
			role:        data.Role,
			serviceName: serviceName,
		}
		return s.validateRecoveryCode(ctx, validate)
	}
	return nil, errs.ErrInvalidCode
}

func (s *AuthService) validTotpCode(
	ctx context.Context,
	validate *validateTwoFactor,
) (*authv1.LoginTwoFactorResponse, error) {
	params := &repository.TwoFactorSecretParams{UserID: validate.userID}
	row, rowErr := s.cfg.Repository.TwoFactorSecret(ctx, params)
	if rowErr != nil {
		if errors.Is(rowErr, pgx.ErrNoRows) {
			s.cfg.Logger.WarnContext(ctx, validate.serviceName+" data not found", "userID", validate.userID.String())
			return nil, errs.ErrNotFound
		}
		s.cfg.Logger.ErrorContext(ctx, validate.serviceName+" secret database", "error", rowErr)
		return nil, errs.ErrInternalServer
	}

	ok, validateErr := s.cfg.TwoFactor.Validate(validate.code, row.Secret)
	if validateErr != nil {
		s.cfg.Logger.ErrorContext(ctx, validate.serviceName+" validation", "error", validateErr)
		return nil, errs.ErrInternalServer
	}
	if !ok {
		s.cfg.Logger.WarnContext(ctx, validate.serviceName+" code error", "userID", validate.userID.String())
		return nil, errs.ErrInvalidCode
	}

	tf := &loginTF{
		userID:      validate.userID,
		session:     validate.session,
		role:        validate.role,
		id:          row.ID,
		updatedAt:   row.UpdatedAt,
		serviceName: validate.serviceName,
		totp:        true,
	}

	return s.loginTwoFactor(ctx, tf)
}

func (s *AuthService) validateRecoveryCode(
	ctx context.Context,
	validate *validateTwoFactor,
) (*authv1.LoginTwoFactorResponse, error) {
	params := &repository.RecoveryCodesParams{UserID: validate.userID}
	row, rowErr := s.cfg.Repository.RecoveryCodes(ctx, params)
	if rowErr != nil {
		s.cfg.Logger.ErrorContext(ctx, validate.serviceName+" recovery code database", "error", rowErr)
		return nil, errs.ErrInternalServer
	}

	if len(row) == 0 {
		s.cfg.Logger.WarnContext(ctx, "Recovery attempt with no codes in DB", "userID", validate.userID)
		return nil, errs.ErrNotFound
	}

	ok, id, updatedAt := s.cfg.TwoFactor.ValidateRecoveryCode(validate.code, row)
	if !ok {
		s.cfg.Logger.WarnContext(
			ctx,
			"Invalid recovery code",
			"userID",
			validate.userID.String(),
			"session",
			validate.session,
		)
		return nil, errs.ErrInvalidCode
	}

	tf := &loginTF{
		userID:      validate.userID,
		session:     validate.session,
		role:        validate.role,
		id:          id,
		updatedAt:   updatedAt,
		serviceName: validate.serviceName,
		totp:        false,
	}

	return s.loginTwoFactor(ctx, tf)
}

func (s *AuthService) loginTwoFactor(ctx context.Context, tf *loginTF) (*authv1.LoginTwoFactorResponse, error) {
	hDErr := redis.HDelete[LoginTwoFactorSession](ctx, LoginTwoFactorSessionPrefix, tf.session, s.cfg.Client)
	if hDErr != nil {
		s.cfg.Logger.ErrorContext(ctx, tf.serviceName+" valkey delete", "error", hDErr)
		return nil, errs.ErrInternalServer
	}

	tx, txErr := s.cfg.Pool.Begin(ctx)
	if txErr != nil {
		s.cfg.Logger.ErrorContext(ctx, tf.serviceName+" transactions", "error", txErr)
		return nil, errs.ErrInternalServer
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	qtx := repository.New(tx)

	if tf.totp {
		if handelErr := handleTwoFactorUpdate(ctx, tf, qtx, s.cfg.Logger); handelErr != nil {
			return nil, handelErr
		}
	} else {
		if handleErr := handleRecoveryCodeUpdate(ctx, tf, qtx, s.cfg.Logger); handleErr != nil {
			return nil, handleErr
		}
	}

	if txCommitErr := tx.Commit(ctx); txCommitErr != nil {
		s.cfg.Logger.ErrorContext(ctx, tf.serviceName+" commit", "error", txCommitErr)
		return nil, errs.ErrInternalServer
	}

	jwt, jwtErr := s.login(
		ctx,
		tf.userID.String(),
		tf.role,
		tf.serviceName,
	)
	if jwtErr != nil {
		return nil, jwtErr
	}

	return &authv1.LoginTwoFactorResponse{
		Token: &authv1.Token{
			Access:   jwt.Access,
			Refresh:  jwt.Refresh,
			ExpireAt: timestamppb.New(jwt.ExpiryAt),
		},
	}, nil
}

func handleTwoFactorUpdate(ctx context.Context, tf *loginTF, qtx *repository.Queries, logger *slog.Logger) error {
	params := &repository.UpdateTwoFactorParams{
		UpdatedBy: tf.userID,
		ID:        tf.id,
		UserID:    tf.userID,
		UpdatedAt: tf.updatedAt,
	}

	update, updateErr := qtx.UpdateTwoFactor(ctx, params)
	if updateErr != nil {
		logger.ErrorContext(ctx, tf.serviceName+"failed to update two factor", "error", updateErr)
		return errs.ErrInternalServer
	}

	if update.RowsAffected() == 0 {
		logger.WarnContext(ctx, tf.serviceName+" cannot update two factor", "userID", tf.userID)
		return errs.ErrInternalServer
	}
	return nil
}

func handleRecoveryCodeUpdate(ctx context.Context, tf *loginTF, qtx *repository.Queries, logger *slog.Logger) error {
	params := &repository.UpdateRecoveryCodeParams{
		ID:        tf.id,
		UserID:    tf.userID,
		UpdatedAt: tf.updatedAt,
	}

	update, updateErr := qtx.UpdateRecoveryCode(ctx, params)
	if updateErr != nil {
		logger.ErrorContext(ctx, tf.serviceName+"failed to update recovery code", "error", updateErr)
		return errs.ErrInternalServer
	}

	if update.RowsAffected() == 0 {
		logger.WarnContext(ctx, tf.serviceName+" cannot update recovery code", "userID", tf.userID)
		return errs.ErrInternalServer
	}

	return nil
}
