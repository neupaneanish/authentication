package service

import (
	"context"

	"github.com/google/uuid"
	"github.com/valkey-io/valkey-go/om"
	"google.golang.org/protobuf/types/known/timestamppb"

	"neupaneanish.com.np/authentication/internal/errs"
	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"
	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/internal/repository"
	"neupaneanish.com.np/authentication/internal/utils"
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
	serviceName string
	totp        bool
}

func (s *ExternalAuthenticationService) LoginTwoFactor(
	ctx context.Context,
	req *externalAuthenticationv1.LoginTwoFactorRequest,
) (*externalAuthenticationv1.LoginTwoFactorResponse, error) {
	serviceName := "LoginTwoFactor"
	session := req.GetSession()

	resultSession, resultSessionErr := s.cfg.RateLimiter.LoginTwoFactor.Allow(ctx, session)
	limiterSessionErr := LimiterCheck(ctx, &resultSession, resultSessionErr, serviceName, session, s.cfg.Logger)
	if limiterSessionErr != nil {
		return nil, limiterSessionErr
	}

	data, dataErr := redis.HGet[utils.LoginTwoFactorSession](
		ctx,
		utils.LoginTwoFactorSessionPrefix,
		session,
		s.cfg.Client,
	)
	if dataErr != nil {
		if om.IsRecordNotFound(dataErr) {
			s.cfg.Logger.WarnContext(ctx, serviceName+" not found", "session", session)
			return nil, errs.ErrSessionExpired
		}
		s.cfg.Logger.ErrorContext(ctx, serviceName+" valkey", "error", dataErr)
		return nil, errs.ErrInternalServer
	}

	result, resultErr := s.cfg.RateLimiter.LoginTwoFactorUserID.Allow(ctx, data.UserID)
	limiterErr := LimiterCheck(ctx, &result, resultErr, serviceName, data.UserID, s.cfg.Logger)
	if limiterErr != nil {
		return nil, limiterErr
	}

	userID := uuid.MustParse(data.UserID)

	switch m := req.GetCode().(type) {
	case *externalAuthenticationv1.LoginTwoFactorRequest_Totp:
		validate := &validateTwoFactor{
			code:        m.Totp,
			userID:      userID,
			session:     session,
			role:        data.Role,
			serviceName: serviceName,
		}
		return s.validTotpCode(ctx, validate)
	case *externalAuthenticationv1.LoginTwoFactorRequest_Recovery:
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

func (s *ExternalAuthenticationService) validTotpCode(
	ctx context.Context,
	validate *validateTwoFactor,
) (*externalAuthenticationv1.LoginTwoFactorResponse, error) {
	if validErr := ValidateTotpCode(
		ctx,
		validate.userID,
		s.cfg.Repository,
		validate.code,
		validate.serviceName,
		s.cfg.TwoFactor,
		s.cfg.Logger,
	); validErr != nil {
		return nil, validErr
	}

	tf := &loginTF{
		userID:      validate.userID,
		session:     validate.session,
		role:        validate.role,
		serviceName: validate.serviceName,
		totp:        true,
	}

	return s.loginTwoFactor(ctx, tf)
}

func (s *ExternalAuthenticationService) validateRecoveryCode(
	ctx context.Context,
	validate *validateTwoFactor,
) (*externalAuthenticationv1.LoginTwoFactorResponse, error) {
	id, err := ValidateRecoveryCode(
		ctx,
		validate.userID,
		s.cfg.Repository,
		validate.code,
		validate.serviceName,
		s.cfg.TwoFactor,
		s.cfg.Logger,
	)
	if err != nil {
		return nil, err
	}

	tf := &loginTF{
		userID:      validate.userID,
		session:     validate.session,
		role:        validate.role,
		id:          id,
		serviceName: validate.serviceName,
		totp:        false,
	}

	return s.loginTwoFactor(ctx, tf)
}

func (s *ExternalAuthenticationService) loginTwoFactor(
	ctx context.Context,
	tf *loginTF,
) (*externalAuthenticationv1.LoginTwoFactorResponse, error) {
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
		if handelErr := s.handleTwoFactorUpdate(ctx, tf, qtx); handelErr != nil {
			return nil, handelErr
		}
	} else {
		if handleErr := s.handleRecoveryCodeUpdate(ctx, tf, qtx); handleErr != nil {
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

	s.twoFactorSessionDelete(ctx, tf.session, tf.serviceName)

	return &externalAuthenticationv1.LoginTwoFactorResponse{
		Token: &externalAuthenticationv1.Token{
			Access:   jwt.Access,
			Refresh:  jwt.Refresh,
			ExpireAt: timestamppb.New(jwt.ExpiryAt),
		},
	}, nil
}

func (s *ExternalAuthenticationService) handleTwoFactorUpdate(
	ctx context.Context,
	tf *loginTF,
	qtx *repository.Queries,
) error {
	params := &repository.UpdateTwoFactorParams{
		UpdatedBy: tf.userID,
		UserID:    tf.userID,
	}

	tag, tagErr := qtx.UpdateTwoFactor(ctx, params)
	if err := AffectedRowCheck(
		ctx,
		tag,
		tagErr,
		"Failed to update Two Factor",
		tf.serviceName,
		1,
		s.cfg.Logger,
	); err != nil {
		return err
	}
	return nil
}

func (s *ExternalAuthenticationService) handleRecoveryCodeUpdate(
	ctx context.Context,
	tf *loginTF,
	qtx *repository.Queries,
) error {
	params := &repository.UpdateRecoveryCodeParams{
		ID:     tf.id,
		UserID: tf.userID,
	}

	tag, tagErr := qtx.UpdateRecoveryCode(ctx, params)
	if err := AffectedRowCheck(
		ctx,
		tag,
		tagErr,
		"Failed to update Recovery Code",
		tf.serviceName,
		1,
		s.cfg.Logger,
	); err != nil {
		return err
	}

	return nil
}

func (s *ExternalAuthenticationService) twoFactorSessionDelete(
	ctx context.Context,
	session string,
	serviceName string,
) {
	if sessionDeleteErr := redis.HDelete[utils.LoginTwoFactorSession](
		ctx,
		utils.LoginTwoFactorSessionPrefix,
		session,
		s.cfg.Client,
	); sessionDeleteErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "Valkey delete", "service", serviceName, "error", sessionDeleteErr)
	}
}
