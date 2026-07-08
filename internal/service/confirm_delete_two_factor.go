package service

import (
	"context"

	"github.com/google/uuid"

	"neupaneanish.com.np/authentication/internal/enum"
	"neupaneanish.com.np/authentication/internal/errs"
	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
	"neupaneanish.com.np/authentication/internal/repository"
	"neupaneanish.com.np/authentication/internal/task"
	"neupaneanish.com.np/authentication/internal/utils"
)

func (s *GatewayAuthenticationService) ConfirmDeleteTwoFactor(
	ctx context.Context,
	req *gatewayAuthenticationv1.ConfirmDeleteTwoFactorRequest,
) (*gatewayAuthenticationv1.ConfirmDeleteTwoFactorResponse, error) {
	serviceName := "ConfirmDeleteTwoFactor"

	securitySession, sessionErr := s.gatewaySecuritySessionVerify(
		ctx,
		serviceName,
		enum.DisableTwoFactor,
		req.GetSession(),
	)
	if sessionErr != nil {
		return nil, sessionErr
	}

	userID := uuid.MustParse(securitySession.Key)

	switch m := req.GetCode().(type) {
	case *gatewayAuthenticationv1.ConfirmDeleteTwoFactorRequest_Totp:
		if err := ValidateTotpCode(
			ctx,
			userID,
			s.cfg.Repository,
			m.Totp,
			serviceName,
			s.cfg.TwoFactor,
			s.cfg.Logger,
		); err != nil {
			return nil, err
		}
	case *gatewayAuthenticationv1.ConfirmDeleteTwoFactorRequest_Recovery:
		if _, err := ValidateRecoveryCode(
			ctx,
			userID,
			s.cfg.Repository,
			m.Recovery,
			serviceName,
			s.cfg.TwoFactor,
			s.cfg.Logger,
		); err != nil {
			return nil, err
		}
	default:
		s.cfg.Logger.WarnContext(ctx, "Invalid one of code", "service", serviceName)
		return nil, errs.ErrInvalidCode
	}

	tfParams := &repository.DeleteTwoFactorParams{UserID: userID}
	recoveryCodesParams := &repository.DeleteRecoveryCodesParams{UserID: userID}
	recoveryCountParams := &repository.RecoveryCodeCountParams{UserID: userID}

	tx, txErr := s.cfg.Pool.Begin(ctx)
	if txErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "transactions", "service", serviceName, "error", txErr)
		return nil, errs.ErrInternalServer
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	qtx := repository.New(tx)

	count, countErr := qtx.RecoveryCodeCount(ctx, recoveryCountParams)
	if countErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "Recovery Count", "service", serviceName, "error", countErr)
		return nil, errs.ErrInternalServer
	}

	tfCmdTag, tfErr := qtx.DeleteTwoFactor(ctx, tfParams)
	if err := AffectedRowCheck(ctx, tfCmdTag, tfErr, "Two Factor Delete", serviceName, 1, s.cfg.Logger); err != nil {
		return nil, err
	}

	recoveryCmdTag, recoveryErr := qtx.DeleteRecoveryCodes(ctx, recoveryCodesParams)
	if err := AffectedRowCheck(
		ctx,
		recoveryCmdTag,
		recoveryErr,
		"Recovery Codes Delete",
		serviceName,
		count,
		s.cfg.Logger,
	); err != nil {
		return nil, err
	}

	if txCommitErr := tx.Commit(ctx); txCommitErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "commit", "service", serviceName, "error", txCommitErr)
		return nil, errs.ErrInternalServer
	}

	s.deleteGatewaySecuritySession(ctx, utils.DeleteTwoFactorSessionPrefix, securitySession.Key, serviceName)

	t, tErr := task.SecurityNotification(task.TypeConfirmDeleteTwoFactor, securitySession.Email)
	_ = EmailEnqueue(ctx, t, tErr, serviceName, s.cfg.Logger, s.cfg.Worker)

	return &gatewayAuthenticationv1.ConfirmDeleteTwoFactorResponse{}, nil
}
