package service

import (
	"context"
	"log/slog"
	"time"
	"uuid"

	"github.com/valkey-io/valkey-go/om"
	"github.com/valkey-io/valkey-go/valkeylimiter"
	"google.golang.org/protobuf/types/known/timestamppb"

	"neupaneanish.com.np/authentication/internal/enum"

	"neupaneanish.com.np/authentication/internal/errs"
	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/internal/utils"

	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"
	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
)

//nolint:funlen
func (s *ExternalAuthenticationService) Resend(
	ctx context.Context,
	req *externalAuthenticationv1.ResendRequest,
) (*externalAuthenticationv1.ResendResponse, error) {
	serviceName := "ResendVerification"
	session := req.GetSession()

	token := utils.GenerateToken(utils.SessionExpiry)

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

	if !enum.Method(verificationSession.Method).Valid() ||
		!enum.VerificationMethod(verificationSession.VerificationMethod).Valid() {
		s.cfg.Logger.WarnContext(
			ctx,
			"Invalid Methods",
			"service",
			serviceName,
			"userID",
			verificationSession.UserID,
			"method",
			verificationSession.Method,
			"verificationMethod",
			verificationSession.VerificationMethod,
		)
		s.deleteVerificationSession(ctx, session, serviceName)
		return nil, errs.ErrSessionExpired
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

	userID, userIDErr := uuid.Parse(verificationSession.UserID)
	if userIDErr != nil {
		s.cfg.Logger.ErrorContext(
			ctx,
			"Invalid UserID in session",
			"service", serviceName,
			"userID", verificationSession.UserID,
			"error", userIDErr,
		)
		s.deleteVerificationSession(ctx, session, serviceName)
		return nil, errs.ErrSessionExpired
	}

	if err := resendError(ctx, verificationSession.ExAt, serviceName, s.cfg.Logger); err != nil {
		return nil, err
	}

	if err := s.verification(
		ctx,
		userID,
		enum.UserRole(verificationSession.Role),
		verificationSession.Username,
		verificationSession.Email,
		serviceName,
		token,
		enum.Method(verificationSession.Method),
		verificationMethod,
		verificationSession.EnabledTwoFactor,
	); err != nil {
		return nil, err
	}
	s.deleteVerificationSession(ctx, session, serviceName)

	return &externalAuthenticationv1.ResendResponse{
		Session: token.Session,
		Expires: timestamppb.New(token.Expires),
	}, nil
}

func (s *GatewayAuthenticationService) Resend(
	ctx context.Context,
	req *gatewayAuthenticationv1.ResendRequest,
) (*gatewayAuthenticationv1.ResendResponse, error) {
	serviceName := "ResendPasswordVerification"
	session := req.GetSession()

	userSession := utils.UserSessionContext(ctx)

	token := utils.GenerateToken(utils.SessionExpiry)

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

	var emailTemplate string

	switch method {
	case enum.SecurityMethodChangePassword:
		emailTemplate = utils.EmailTemplateChangePassword
	case enum.SecurityMethodEnableTwoFactor:
		emailTemplate = utils.EmailTemplateEnableTwoFactor
	case enum.SecurityMethodDisableTwoFactor:
		emailTemplate = utils.EmailTemplateDisableTwoFactor
	case enum.SecurityMethodChangeEmail:
		emailTemplate = utils.EmailTemplateChangeEmail
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

	if err := resendError(ctx, verificationSession.ExAt, serviceName, s.cfg.Logger); err != nil {
		return nil, err
	}

	s.deletePasswordVerificationSession(ctx, userSession.UserID.String(), serviceName)

	if err := s.passwordVerification(
		ctx,
		userSession.UserID,
		verificationSession.Email,
		emailTemplate,
		serviceName,
		token,
		method,
	); err != nil {
		return nil, err
	}

	return &gatewayAuthenticationv1.ResendResponse{
		Session: token.Session,
		Expires: timestamppb.New(token.Expires),
	}, nil
}

func resendError(ctx context.Context, sessionTime time.Time, serviceName string, logger *slog.Logger) error {
	remainingTime := sessionTime.Sub(time.Now().UTC())
	if remainingTime >= 3*time.Minute {
		logger.WarnContext(
			ctx,
			"Request before 2 minutes passed",
			"service", serviceName,
			"remaining", remainingTime.String(),
		)
		return errs.ErrResend
	}
	return nil
}
