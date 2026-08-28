package service

import (
	"context"
	"crypto/rand"

	"uuid"

	"github.com/valkey-io/valkey-go/om"
	"github.com/valkey-io/valkey-go/valkeylimiter"

	"neupaneanish.com.np/authentication/internal/task"

	"neupaneanish.com.np/authentication/internal/enum"

	"neupaneanish.com.np/authentication/internal/errs"
	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/internal/utils"

	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"
	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
)

func (s *ExternalAuthenticationService) Resend(
	ctx context.Context,
	req *externalAuthenticationv1.ResendRequest,
) (*externalAuthenticationv1.ResendResponse, error) {
	serviceName := "ResendVerification"
	session := req.GetSession()

	newSession := rand.Text()

	var result valkeylimiter.Result
	var resultErr error

	result, resultErr = s.cfg.RateLimiter.ResendVerification.Allow(ctx, session)
	if err := LimiterCheck(ctx, &result, resultErr, serviceName, session, s.cfg.Logger); err != nil {
		return nil, err
	}

	verificationSession, verificationSessionErr := redis.HGet[utils.VerificationSession](
		ctx,
		utils.VerificationSessionPrefix,
		session,
		s.cfg.Client,
	)
	if verificationSessionErr != nil {
		if om.IsRecordNotFound(verificationSessionErr) {
			s.cfg.Logger.ErrorContext(ctx, "Session not found", "service", serviceName, "error", verificationSessionErr)
			return nil, errs.ErrSessionExpired
		}
		s.cfg.Logger.ErrorContext(ctx, "Valkey Get", "service", serviceName, "error", verificationSessionErr)
		return nil, errs.ErrInternalServer
	}

	result, resultErr = s.cfg.RateLimiter.ResendVerificationUserID.Allow(ctx, verificationSession.UserID)
	if err := LimiterCheck(ctx, &result, resultErr, serviceName, verificationSession.UserID, s.cfg.Logger); err != nil {
		return nil, err
	}

	verificationMethod := enum.VerificationMethod(verificationSession.VerificationMethod)
	if verificationMethod == enum.VerificationMethodTwoFactor {
		s.cfg.Logger.WarnContext(
			ctx,
			"Resend on Two Factor",
			"service",
			serviceName,
			"userID",
			verificationSession.UserID,
		)
		s.deleteVerificationSession(ctx, session, serviceName)
		return nil, errs.ErrSessionExpired
	}

	if err := s.verification(
		ctx,
		uuid.MustParse(verificationSession.UserID),
		enum.UserRole(verificationSession.Role),
		verificationSession.Email,
		newSession,
		serviceName,
		enum.Method(verificationSession.Method),
		verificationMethod,
		verificationSession.EnabledTwoFactor,
	); err != nil {
		return nil, err
	}

	return &externalAuthenticationv1.ResendResponse{
		Session: newSession,
	}, nil
}

func (s *GatewayAuthenticationService) Resend(
	ctx context.Context,
	req *gatewayAuthenticationv1.ResendRequest,
) (*gatewayAuthenticationv1.ResendResponse, error) {
	serviceName := "ResendPasswordVerification"
	session := req.GetSession()

	userSession, userSessionErr := utils.GetUserSessionContext(ctx, serviceName, s.cfg.Logger)
	if userSessionErr != nil {
		return nil, userSessionErr
	}

	newSession := rand.Text()

	var result valkeylimiter.Result
	var resultErr error

	result, resultErr = s.cfg.RateLimiter.ResendVerification.Allow(ctx, session)
	if err := LimiterCheck(ctx, &result, resultErr, serviceName, session, s.cfg.Logger); err != nil {
		return nil, err
	}

	verificationSession, verificationSessionErr := redis.HGet[utils.PasswordVerificationSession](
		ctx,
		utils.PasswordVerificationSessionPrefix,
		userSession.UserID.String(),
		s.cfg.Client,
	)
	if verificationSessionErr != nil {
		if om.IsRecordNotFound(verificationSessionErr) {
			s.cfg.Logger.ErrorContext(ctx, "Session not found", "service", serviceName, "error", verificationSessionErr)
			return nil, errs.ErrSessionExpired
		}
		s.cfg.Logger.ErrorContext(ctx, "Valkey Get", "service", serviceName, "error", verificationSessionErr)
		return nil, errs.ErrInternalServer
	}

	result, resultErr = s.cfg.RateLimiter.ResendPasswordVerificationUserID.Allow(ctx, verificationSession.Key)
	if err := LimiterCheck(ctx, &result, resultErr, serviceName, verificationSession.Key, s.cfg.Logger); err != nil {
		return nil, err
	}

	if session != verificationSession.Session {
		s.cfg.Logger.WarnContext(ctx, "Invalid Session", "service", serviceName)
		return nil, errs.ErrUnauthenticated
	}

	method := enum.SecurityMethod(verificationSession.Method)

	var emailType string

	switch method {
	case enum.SecurityMethodChangePassword:
		emailType = task.TypeChangePassword
	case enum.SecurityMethodEnableTwoFactor:
		emailType = task.TypeEnableTwoFactor
	case enum.SecurityMethodDisableTwoFactor:
		emailType = task.TypeDisableTwoFactor
	default:
		s.cfg.Logger.WarnContext(ctx, "Invalid Method", "service", serviceName)
		s.deletePasswordVerificationSession(ctx, userSession.UserID.String(), serviceName)
		return nil, errs.ErrUnauthenticated
	}

	if method == enum.SecurityMethodDisableTwoFactor {
		s.cfg.Logger.WarnContext(ctx, "Resend on Disable Two Factor", "service", serviceName)
		s.deletePasswordVerificationSession(ctx, userSession.UserID.String(), serviceName)
		return nil, errs.ErrUnauthenticated
	}

	s.deletePasswordVerificationSession(ctx, userSession.UserID.String(), serviceName)

	if err := s.passwordVerification(
		ctx,
		verificationSession.Key,
		verificationSession.Email,
		newSession,
		emailType,
		serviceName,
		method,
	); err != nil {
		return nil, err
	}
	return &gatewayAuthenticationv1.ResendResponse{
		Session: newSession,
	}, nil
}
