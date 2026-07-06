package service

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/valkey-io/valkey-go/om"
	"neupaneanish.com.np/authentication/internal/enum"
	"neupaneanish.com.np/authentication/internal/errs"
	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/internal/repository"
	"neupaneanish.com.np/authentication/internal/task"
	"neupaneanish.com.np/authentication/internal/utils"
)

func (s *GatewayAuthenticationService) ConfirmTwoFactor(
	ctx context.Context,
	req *gatewayAuthenticationv1.ConfirmTwoFactorRequest,
) (*gatewayAuthenticationv1.ConfirmTwoFactorResponse, error) {
	serviceName := "ConfirmTwoFactor"
	userSession, _, _, err := s.gatewayUserSessionLimiter(ctx, serviceName, enum.TwoFactor)
	if err != nil {
		return nil, err
	}

	data, dataErr := redis.HGet[utils.GatewaySecurityVerificationTwoFactorSession](
		ctx,
		utils.VerifyTwoFactorSessionPrefix,
		userSession.UserID.String(),
		s.cfg.Client,
	)

	if dataErr != nil {
		if om.IsRecordNotFound(dataErr) {
			s.cfg.Logger.WarnContext(ctx, "session expired", "service", serviceName)
			return nil, errs.ErrSessionExpired
		}
		s.cfg.Logger.ErrorContext(ctx, "Valkey get", "service", serviceName, "error", dataErr)
		return nil, errs.ErrInternalServer
	}

	if data.Session != req.GetSession() {
		s.cfg.Logger.WarnContext(ctx, "session expired", "service", serviceName)
		return nil, errs.ErrSessionExpired
	}

	valid, validateErr := s.cfg.TwoFactor.Validate(req.GetCode(), data.Secret)
	if validateErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "Validation", "service", serviceName, "error", validateErr)
		return nil, errs.ErrInternalServer
	}
	if !valid {
		s.cfg.Logger.WarnContext(ctx, "Invalid code", "service", serviceName)
		return nil, errs.ErrInvalidCode
	}
	codes, codesErr := s.cfg.TwoFactor.GenerateRecoveryCodes()
	if codesErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "Recovery Code Generation", "service", serviceName, "error", codesErr)
		return nil, errs.ErrInternalServer
	}

	if confirmErr := s.confirmTwoFactorDatabase(
		ctx,
		userSession.UserID,
		data.Secret,
		serviceName,
		codes.Hash,
	); confirmErr != nil {
		return nil, confirmErr
	}

	t, tErr := task.SecurityNotification(task.TypeConfirmTwoFactor, data.Email)
	_ = EmailEnqueue(ctx, t, tErr, serviceName, s.cfg.Logger, s.cfg.Worker) // Error already handled by EmailEnqueue

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

	cmdTag, secretErr := qtx.CreateTwoFactor(ctx, twoFactorParams)
	if secretErr != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](secretErr); ok {
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
		s.cfg.Logger.ErrorContext(ctx, "Create Two Factor", "service", serviceName, "error", secretErr)
		return errs.ErrInternalServer
	}

	if cmdTag.RowsAffected() == 0 {
		s.cfg.Logger.WarnContext(ctx, "Cannot create", "service", serviceName)
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
	if hDeleteErr := redis.HDelete[utils.GatewaySecurityVerificationTwoFactorSession](
		ctx,
		utils.VerifyTwoFactorSessionPrefix,
		userID.String(),
		s.cfg.Client,
	); hDeleteErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "Valkey delete setup session", "service", serviceName, "error", hDeleteErr)
	}
	return nil
}
