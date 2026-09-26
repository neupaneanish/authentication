package service

import (
	"context"
	"errors"

	"uuid"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"

	"neupaneanish.com.np/authentication/internal/redpanda"

	"neupaneanish.com.np/authentication/internal/errs"
	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/internal/repository"
	"neupaneanish.com.np/authentication/internal/utils"
)

func (s *GatewayAuthenticationService) ConfirmTwoFactor(
	ctx context.Context,
	req *gatewayAuthenticationv1.ConfirmTwoFactorRequest,
) (*gatewayAuthenticationv1.ConfirmTwoFactorResponse, error) {
	serviceName := "ConfirmTwoFactor"

	userSession := utils.UserSessionContext(ctx)

	result, resultErr := s.cfg.RateLimiter.TwoFactorWorkflow.Allow(ctx, userSession.UserID.String())
	if err := LimiterCheck(
		ctx,
		&result,
		resultErr,
		serviceName,
		userSession.UserID.String(),
		s.cfg.Logger,
	); err != nil {
		return nil, err
	}

	tfSession, tfSessionErr := redis.HGet[utils.EnableTwoFactorSession](
		ctx,
		utils.TwoFactorSessionPrefix,
		userSession.UserID.String(),
		s.cfg.Client,
	)

	if err := omNotFound(ctx, tfSessionErr, serviceName, s.cfg.Logger); err != nil {
		return nil, err
	}

	if tfSession.Session != req.GetSession() {
		s.cfg.Logger.WarnContext(ctx, "Session not match", "service", serviceName)
		s.deleteConfirmTwoFactorSession(ctx, tfSession.Key, serviceName)
		return nil, errs.ErrSessionExpired
	}

	valid, validateErr := s.cfg.TwoFactor.Validate(req.GetCode(), tfSession.Secret)
	if validateErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "Validation", "service", serviceName, "error", validateErr)
		return nil, errs.ErrInternalServer
	}
	if !valid {
		s.cfg.Logger.WarnContext(ctx, "Invalid code", "service", serviceName)
		return nil, errs.ErrInvalidCode
	}
	codes, codesErr := s.cfg.TwoFactor.GenerateRecoveryCodes(ctx)
	if codesErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "Recovery Code Generation", "service", serviceName, "error", codesErr)
		return nil, errs.ErrInternalServer
	}

	if confirmErr := s.confirmTwoFactorDatabase(
		ctx,
		userSession.UserID,
		tfSession.Secret,
		serviceName,
		codes.Hash,
	); confirmErr != nil {
		return nil, confirmErr
	}

	redpanda.SecurityEmailProduce(
		ctx,
		userSession.UserID,
		tfSession.Email,
		utils.EmailTemplateConfirmTwoFactor,
		serviceName,
		s.cfg.Redpanda,
		s.cfg.Logger,
	)
	redpanda.RootNotificationProduce(
		ctx,
		userSession,
		userSession.UserID,
		utils.DatabaseTableTwoFactor,
		utils.DatabaseMethodCreate,
		serviceName,
		s.cfg.Client,
		s.cfg.Redpanda,
		s.cfg.Logger,
	)
	return &gatewayAuthenticationv1.ConfirmTwoFactorResponse{Codes: codes.Plain}, nil
}

func (s *GatewayAuthenticationService) confirmTwoFactorDatabase(
	ctx context.Context,
	userID uuid.UUID,
	secret []byte,
	serviceName string,
	codes [][]byte,
) error {
	twoFactorParams := &repository.CreateTwoFactorParams{
		UserID:    userID,
		Secret:    secret,
		CreatedBy: userID,
		UpdatedBy: userID,
	}

	recoveryCodesRows := make([]*repository.CreateRecoveryCodesParams, 0, len(codes))
	for _, hash := range codes {
		recoveryCodesRows = append(recoveryCodesRows, &repository.CreateRecoveryCodesParams{
			UserID:    userID,
			Code:      hash,
			CreatedBy: userID,
			UpdatedBy: userID,
		})
	}
	tx, txErr := s.cfg.Pool.Begin(ctx)
	if txErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "transactions", "service", serviceName, "error", txErr)
		return errs.ErrInternalServer
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	qtx := repository.New(tx)

	if err := qtx.CreateTwoFactor(ctx, twoFactorParams); err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok {
			switch pgErr.Code {
			case pgerrcode.UniqueViolation:
				s.cfg.Logger.WarnContext(
					ctx,
					"Tried to enable again",
					"service",
					serviceName,
				)
				return errs.ErrAlreadyEnabled
			case pgerrcode.ForeignKeyViolation:
				s.cfg.Logger.ErrorContext(
					ctx,
					"User does not exist in core system",
					"service",
					serviceName,
				)
				return errs.ErrSessionExpired
			}
		}
		s.cfg.Logger.ErrorContext(ctx, "Create Two Factor", "service", serviceName, "error", err)
		return errs.ErrInternalServer
	}

	recovery, recoveryErr := qtx.CreateRecoveryCodes(ctx, recoveryCodesRows)
	if recoveryErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "Create Recovery codes", "service", serviceName, "error", recoveryErr)
		return errs.ErrInternalServer
	}

	if recovery != int64(len(codes)) {
		s.cfg.Logger.ErrorContext(ctx, "Create Recovery codes length miss match", "service", serviceName,
			"expected", len(codes),
			"inserted", recovery,
		)
		return errs.ErrInternalServer
	}
	if txCommitErr := tx.Commit(ctx); txCommitErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "commit", "service", serviceName, "error", txCommitErr)
		return errs.ErrInternalServer
	}
	s.deleteConfirmTwoFactorSession(ctx, userID.String(), serviceName)
	return nil
}

func (s *GatewayAuthenticationService) deleteConfirmTwoFactorSession(ctx context.Context, key, serviceName string) {
	if err := redis.HDelete[utils.EnableTwoFactorSession](
		ctx,
		utils.TwoFactorSessionPrefix,
		key,
		s.cfg.Client,
	); err != nil {
		s.cfg.Logger.ErrorContext(ctx, "Valkey delete setup session", "service", serviceName, "error", err)
	}
}
