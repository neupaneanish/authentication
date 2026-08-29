package service

import (
	"context"
	"crypto/rand"
	"time"

	"uuid"

	"github.com/valkey-io/valkey-go/om"
	"github.com/valkey-io/valkey-go/valkeylimiter"

	"neupaneanish.com.np/authentication/internal/enum"

	"neupaneanish.com.np/authentication/internal/task"

	"neupaneanish.com.np/authentication/internal/repository"

	"neupaneanish.com.np/authentication/internal/errs"
	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/internal/utils"
)

func (s *GatewayAuthenticationService) PasswordSessionVerification(
	ctx context.Context,
	req *gatewayAuthenticationv1.PasswordSessionVerificationRequest,
) (*gatewayAuthenticationv1.PasswordSessionVerificationResponse, error) {
	serviceName := "PasswordSessionVerification"

	userSession := utils.UserSessionContext(ctx)

	verificationSession, verificationSessionErr := redis.HGet[utils.PasswordVerificationSession](
		ctx,
		utils.PasswordVerificationSessionPrefix,
		userSession.UserID.String(),
		s.cfg.Client,
	)
	if verificationSessionErr != nil {
		if om.IsRecordNotFound(verificationSessionErr) {
			s.cfg.Logger.WarnContext(ctx, "session expired", "service", serviceName)
			return nil, errs.ErrSessionExpired
		}
		s.cfg.Logger.ErrorContext(ctx, "valkey", "service", serviceName, "error", verificationSessionErr)
		return nil, errs.ErrInternalServer
	}

	if err := s.passwordSessionVerificationRateLimiter(
		ctx,
		verificationSession.Method,
		verificationSession.Key,
		serviceName,
	); err != nil {
		return nil, err
	}

	if req.GetSession() != verificationSession.Session {
		s.cfg.Logger.ErrorContext(ctx, "Invalid session", "service", serviceName)
		s.deletePasswordVerificationSession(ctx, userSession.UserID.String(), serviceName)
		return nil, errs.ErrUnauthenticated
	}

	if err := s.passwordSessionVerificationCodeCheck(
		ctx,
		req,
		userSession.UserID,
		verificationSession.Method,
		verificationSession.Code,
		serviceName,
	); err != nil {
		return nil, err
	}

	newSession := rand.Text()

	switch enum.SecurityMethod(verificationSession.Method) {
	case enum.SecurityMethodDisableTwoFactor:
		return s.disableTwoFactor(ctx, userSession.UserID, serviceName, verificationSession.Email)

	case enum.SecurityMethodChangePassword:
		return s.changePasswordSession(ctx, verificationSession.Key, newSession, verificationSession.Email, serviceName)

	case enum.SecurityMethodEnableTwoFactor:
		return s.enableTwoFactor(ctx, verificationSession.Key, newSession, verificationSession.Email, serviceName)

	default:
		s.cfg.Logger.ErrorContext(ctx, "Invalid method", "service", serviceName)
		s.deletePasswordVerificationSession(ctx, userSession.UserID.String(), serviceName)
		return nil, errs.ErrUnauthenticated
	}
}

func (s *GatewayAuthenticationService) disableTwoFactor(
	ctx context.Context,
	userID uuid.UUID,
	serviceName string,
	email string,
) (*gatewayAuthenticationv1.PasswordSessionVerificationResponse, error) {
	twoFactorParams := &repository.DeleteTwoFactorParams{UserID: userID}
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

	tfCmdTag, tfErr := qtx.DeleteTwoFactor(ctx, twoFactorParams)
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

	s.deletePasswordVerificationSession(ctx, userID.String(), serviceName)

	t, tErr := task.SecurityNotification(task.TypeConfirmDeleteTwoFactor, email)
	_ = EmailEnqueue(ctx, t, tErr, serviceName, s.cfg.Logger, s.cfg.Worker)

	return &gatewayAuthenticationv1.PasswordSessionVerificationResponse{
		Response: &gatewayAuthenticationv1.PasswordSessionVerificationResponse_DisabledTwoFactor{
			DisabledTwoFactor: true,
		},
	}, nil
}

func (s *GatewayAuthenticationService) changePasswordSession(
	ctx context.Context,
	userID, session, email, serviceName string,
) (*gatewayAuthenticationv1.PasswordSessionVerificationResponse, error) {
	data := &utils.ChangePasswordSession{
		Key:     userID,
		ExAt:    time.Now().Add(utils.SessionExpiry),
		Session: session,
		Email:   email,
	}

	if err := redis.HSet[utils.ChangePasswordSession](
		ctx,
		utils.ChangePasswordSessionPrefix,
		data,
		s.cfg.Client,
	); err != nil {
		s.cfg.Logger.ErrorContext(ctx, "Valkey set", "service", serviceName, "error", err)
		return nil, errs.ErrInternalServer
	}

	s.deletePasswordVerificationSession(ctx, userID, serviceName)

	return &gatewayAuthenticationv1.PasswordSessionVerificationResponse{
		Response: &gatewayAuthenticationv1.PasswordSessionVerificationResponse_ChangePassword{
			ChangePassword: session,
		},
	}, nil
}

func (s *GatewayAuthenticationService) enableTwoFactor(
	ctx context.Context,
	userID,
	session,
	email,
	serviceName string,
) (*gatewayAuthenticationv1.PasswordSessionVerificationResponse, error) {
	tfa, err := s.cfg.TwoFactor.Generate(email)
	if err != nil {
		s.cfg.Logger.ErrorContext(ctx, "Two Factor generate", "service", serviceName, "error", err)
		return nil, errs.ErrInternalServer
	}

	data := &utils.EnableTwoFactorSession{
		Key:     userID,
		ExAt:    time.Now().Add(utils.SessionExpiry),
		Session: session,
		Email:   email,
		Secret:  tfa.Encrypt,
	}

	if setErr := redis.HSet[utils.EnableTwoFactorSession](
		ctx,
		utils.TwoFactorSessionPrefix,
		data,
		s.cfg.Client,
	); setErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "Valkey set", "service", serviceName, "error", setErr)
		return nil, errs.ErrInternalServer
	}

	s.deletePasswordVerificationSession(ctx, userID, serviceName)

	return &gatewayAuthenticationv1.PasswordSessionVerificationResponse{
		Response: &gatewayAuthenticationv1.PasswordSessionVerificationResponse_EnableTwoFactor{
			EnableTwoFactor: &gatewayAuthenticationv1.EnableTwoFactor{
				Session: session,
				Uri:     tfa.URL,
				Key:     tfa.Secret,
			},
		},
	}, nil
}

func (s *GatewayAuthenticationService) passwordSessionVerificationRateLimiter(
	ctx context.Context,
	method, userID, serviceName string,
) error {
	var result valkeylimiter.Result
	var resultErr error

	switch enum.SecurityMethod(method) {
	case enum.SecurityMethodChangePassword:
		result, resultErr = s.cfg.RateLimiter.PasswordWorkflow.Allow(ctx, userID)
	case enum.SecurityMethodEnableTwoFactor,
		enum.SecurityMethodDisableTwoFactor:
		result, resultErr = s.cfg.RateLimiter.TwoFactorWorkflow.Allow(ctx, userID)
	default:
		s.cfg.Logger.ErrorContext(ctx, "Invalid method", "service", serviceName)
		s.deletePasswordVerificationSession(ctx, userID, serviceName)
		return errs.ErrUnauthenticated
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

func (s *GatewayAuthenticationService) passwordSessionVerificationCodeCheck(
	ctx context.Context,
	req *gatewayAuthenticationv1.PasswordSessionVerificationRequest,
	userID uuid.UUID,
	method, sessionCode, serviceName string,
) error {
	switch enum.SecurityMethod(method) {
	case enum.SecurityMethodChangePassword,
		enum.SecurityMethodEnableTwoFactor:
		switch code := req.GetCode().(type) {
		case *gatewayAuthenticationv1.PasswordSessionVerificationRequest_Email:
			if sessionCode != code.Email {
				s.cfg.Logger.ErrorContext(ctx, "Invalid code", "service", serviceName)
				return errs.ErrInvalidCode
			}
		default:
			s.cfg.Logger.ErrorContext(ctx, "Invalid Code Method", "service", serviceName, "SecurityMethod", method)
			s.deletePasswordVerificationSession(ctx, userID.String(), serviceName)
			return errs.ErrUnauthenticated
		}

	case enum.SecurityMethodDisableTwoFactor:
		switch code := req.GetCode().(type) {
		case *gatewayAuthenticationv1.PasswordSessionVerificationRequest_Totp:
			if err := ValidateTotpCode(
				ctx,
				userID,
				s.cfg.Repository,
				code.Totp,
				serviceName,
				s.cfg.TwoFactor,
				s.cfg.Logger,
			); err != nil {
				return err
			}
		case *gatewayAuthenticationv1.PasswordSessionVerificationRequest_Recovery:
			if _, err := ValidateRecoveryCode(
				ctx,
				userID,
				s.cfg.Repository,
				code.Recovery,
				serviceName,
				s.cfg.TwoFactor,
				s.cfg.Logger,
			); err != nil {
				return err
			}
		default:
			s.cfg.Logger.ErrorContext(ctx, "Invalid Code Method", "service", serviceName, "SecurityMethod", method)
			s.deletePasswordVerificationSession(ctx, userID.String(), serviceName)
			return errs.ErrUnauthenticated
		}
	}
	return nil
}

func (s *GatewayAuthenticationService) deletePasswordVerificationSession(
	ctx context.Context,
	userID, serviceName string,
) {
	if hDeleteErr := redis.HDelete[utils.PasswordVerificationSession](
		ctx,
		utils.PasswordVerificationSessionPrefix,
		userID,
		s.cfg.Client,
	); hDeleteErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "Delete", "service", serviceName, "error", hDeleteErr)
	}
}
