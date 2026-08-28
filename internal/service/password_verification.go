package service

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5"
	"github.com/valkey-io/valkey-go/valkeylimiter"

	"neupaneanish.com.np/authentication/internal/enum"

	"neupaneanish.com.np/authentication/internal/task"

	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/internal/repository"

	"neupaneanish.com.np/authentication/internal/errs"
	"neupaneanish.com.np/authentication/internal/utils"

	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
)

func (s *GatewayAuthenticationService) PasswordVerification(
	ctx context.Context,
	req *gatewayAuthenticationv1.PasswordVerificationRequest,
) (*gatewayAuthenticationv1.PasswordVerificationResponse, error) {
	serviceName := "PasswordVerification"

	userSession, userSessionErr := utils.GetUserSessionContext(ctx, serviceName, s.cfg.Logger)
	if userSessionErr != nil {
		return nil, userSessionErr
	}

	securityMethod, emailType, rateErr := s.passwordVerificationRateLimiter(
		ctx,
		req.GetMethod(),
		userSession.UserID.String(),
		serviceName,
	)
	if rateErr != nil {
		return nil, rateErr
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
			if logoutAllErr := s.logoutAll(ctx, userSession.UserID.String(), serviceName); logoutAllErr != nil {
				s.cfg.Logger.ErrorContext(
					ctx,
					"Valkey Logout",
					"service",
					serviceName,
					"userID",
					userSession.UserID.String(),
					"error", logoutAllErr,
				)
			}
			return nil, errs.ErrSessionExpired
		}
		s.cfg.Logger.ErrorContext(ctx, "Postgres get", "service", serviceName, "error", rowErr)
		return nil, errs.ErrInternalServer
	}

	if !utils.ComparePassword(row.Password, req.GetPassword().GetValue()) {
		s.cfg.Logger.WarnContext(
			ctx,
			"Invalid Password",
			"service",
			serviceName,
			"userID",
			userSession.UserID.String(),
		)
		return nil, errs.ErrInvalidPassword
	}

	session := rand.Text()
	if err := s.passwordVerification(
		ctx,
		userSession.UserID.String(),
		row.Email,
		session,
		emailType,
		serviceName,
		securityMethod,
	); err != nil {
		return nil, err
	}
	return &gatewayAuthenticationv1.PasswordVerificationResponse{Session: session}, nil
}

func (s *GatewayAuthenticationService) passwordVerificationRateLimiter(
	ctx context.Context,
	method gatewayAuthenticationv1.PasswordVerificationMethod,
	userID,
	serviceName string,
) (enum.SecurityMethod, string, error) {
	var result valkeylimiter.Result
	var resultErr error
	var securityMethod enum.SecurityMethod
	var emailType string

	switch method {
	case gatewayAuthenticationv1.PasswordVerificationMethod_PASSWORD_VERIFICATION_METHOD_CHANGE:
		result, resultErr = s.cfg.RateLimiter.PasswordWorkflow.Allow(ctx, userID)
		emailType = task.TypeChangePassword
		securityMethod = enum.SecurityMethodChangePassword
	case gatewayAuthenticationv1.PasswordVerificationMethod_PASSWORD_VERIFICATION_METHOD_ENABLED,
		gatewayAuthenticationv1.PasswordVerificationMethod_PASSWORD_VERIFICATION_METHOD_DISABLED:
		result, resultErr = s.cfg.RateLimiter.TwoFactorWorkflow.Allow(ctx, userID)
		if method == gatewayAuthenticationv1.PasswordVerificationMethod_PASSWORD_VERIFICATION_METHOD_ENABLED {
			emailType = task.TypeEnableTwoFactor
			securityMethod = enum.SecurityMethodEnableTwoFactor
		} else {
			emailType = task.TypeDisableTwoFactor
			securityMethod = enum.SecurityMethodDisableTwoFactor
		}
	case gatewayAuthenticationv1.PasswordVerificationMethod_PASSWORD_VERIFICATION_METHOD_UNSPECIFIED:
	default:
		s.cfg.Logger.ErrorContext(ctx, "Invalid method", "service", serviceName)
		return "", "", errs.ErrInvalidMethod
	}

	if limiterErr := LimiterCheck(
		ctx,
		&result,
		resultErr,
		serviceName,
		userID,
		s.cfg.Logger,
	); limiterErr != nil {
		return "", "", limiterErr
	}
	return securityMethod, emailType, nil
}

func (s *GatewayAuthenticationService) passwordVerification(
	ctx context.Context,
	userID,
	email,
	session,
	emailType,
	serviceName string,
	securityMethod enum.SecurityMethod,
) error {
	code, plain, codeErr := GenerateEmailCode(ctx, s.cfg.Logger)
	if codeErr != nil {
		return codeErr
	}

	data := &utils.PasswordVerificationSession{
		Key:     userID,
		ExAt:    time.Now().Add(utils.SessionExpiry),
		Code:    code,
		Email:   email,
		Session: session,
		Method:  string(securityMethod),
	}

	if hSetErr := redis.HSet[utils.PasswordVerificationSession](
		ctx,
		utils.PasswordVerificationSessionPrefix,
		data,
		s.cfg.Client,
	); hSetErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "Valkey HSet", "service", serviceName, "error", hSetErr)
		return errs.ErrInternalServer
	}

	var tErr error
	var t *asynq.Task

	if securityMethod == enum.SecurityMethodDisableTwoFactor {
		t, tErr = task.SecurityNotification(emailType, email)
	} else {
		t, tErr = task.AuthEmailTask(emailType, email, plain)
	}

	_ = EmailEnqueue(ctx, t, tErr, serviceName, s.cfg.Logger, s.cfg.Worker) // Error already handled by EmailEnqueue
	return nil
}
