package service

import (
	"context"
	"crypto/rand"

	"github.com/google/uuid"
	"github.com/valkey-io/valkey-go/om"
	"google.golang.org/protobuf/types/known/timestamppb"
	"neupaneanish.com.np/api/internal/enum"
	"neupaneanish.com.np/api/internal/errs"
	authv1 "neupaneanish.com.np/api/internal/protobuf/auth/v1"
	"neupaneanish.com.np/api/internal/redis"
	"neupaneanish.com.np/api/internal/repository"
	"neupaneanish.com.np/api/internal/utils"
)

func (s *AuthService) AccountVerification(
	ctx context.Context,
	req *authv1.AccountVerificationRequest,
) (*authv1.AccountVerificationResponse, error) {
	serviceName := "Account Verification"
	session := req.GetSession()

	accountSession, accountSessionErr := s.accountVerificationSessionCheck(ctx, session, serviceName)
	if accountSessionErr != nil {
		return nil, accountSessionErr
	}

	if req.GetCode() != accountSession.Code {
		s.cfg.Logger.WarnContext(ctx, "Code not match", "service", serviceName, "userID", accountSession.UserID)
		return nil, errs.ErrInvalidCode
	}

	switch enum.Method(accountSession.Method) {
	case enum.MethodRegister:
		return s.accountVerificationMethodRegister(ctx, accountSession, serviceName)
	case enum.MethodForgetPassword:
		return s.accountVerificationMethodForgetPassword(ctx, accountSession, serviceName)
	case enum.MethodLogin:
		return s.accountVerificationMethodLogin(ctx, accountSession, serviceName)
	default:
		s.deleteAccountVerificationSession(ctx, session, serviceName)
		s.cfg.Logger.WarnContext(ctx, "invalid method", "service", serviceName, "method", accountSession.Method)
		return nil, errs.ErrSessionExpired
	}
}

func (s *AuthService) deleteAccountVerificationSession(
	ctx context.Context,
	session string,
	serviceName string,
) {
	hDeleteErr := redis.HDelete[utils.AccountVerificationSession](
		ctx,
		utils.AccountVerificationSessionPrefix,
		session,
		s.cfg.Client,
	)
	if hDeleteErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "Session delete", "service", serviceName, "error", hDeleteErr)
	}
}

func (s *AuthService) accountVerificationLogin(
	ctx context.Context,
	userID string,
	role string,
	serviceName string,
	session string,
) (*authv1.AccountVerificationResponse, error) {
	token, tokenErr := s.login(
		ctx,
		userID,
		role,
		serviceName,
	)
	if tokenErr != nil {
		return nil, tokenErr
	}

	if verifyEmailErr := s.verifyEmail(ctx, userID, serviceName); verifyEmailErr != nil {
		return nil, verifyEmailErr
	}

	s.deleteAccountVerificationSession(ctx, session, serviceName)
	return &authv1.AccountVerificationResponse{
		Response: &authv1.AccountVerificationResponse_Token{
			Token: &authv1.Token{
				Access:   token.Access,
				Refresh:  token.Refresh,
				ExpireAt: timestamppb.New(token.ExpiryAt),
			},
		},
	}, nil
}

func (s *AuthService) verifyEmail(
	ctx context.Context,
	userIDStr string,
	serviceName string,
) error {
	userID := uuid.MustParse(userIDStr)
	verifyEmailParams := &repository.VerifyEmailParams{
		Status:    enum.UserStatusActive,
		UpdatedBy: uuid.Nil,
		ID:        userID,
	}

	result, resultErr := s.cfg.Repository.VerifyEmail(ctx, verifyEmailParams)
	if resultErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "Verify Email", "service", serviceName, "error", resultErr)
		return errs.ErrInternalServer
	}
	if result.RowsAffected() == 0 {
		s.cfg.Logger.WarnContext(
			ctx,
			"Account already verified / account not found",
			"service",
			serviceName,
			"userID",
			userIDStr,
		)
		return errs.ErrAccountAlreadyVerified
	}
	return nil
}

func (s *AuthService) accountVerificationMethodRegister(
	ctx context.Context,
	accountSession *utils.AccountVerificationSession,
	serviceName string,
) (*authv1.AccountVerificationResponse, error) {
	if accountSession.TwoFactor {
		s.cfg.Logger.WarnContext(
			ctx,
			"New account cannot be Two Factor enabled",
			"service",
			serviceName,
			"userID",
			accountSession.UserID,
		)
		s.deleteAccountVerificationSession(ctx, accountSession.Key, serviceName)
		return nil, errs.ErrSessionExpired
	}
	return s.accountVerificationLogin(
		ctx,
		accountSession.UserID,
		accountSession.Role,
		serviceName,
		accountSession.Key,
	)
}

func (s *AuthService) accountVerificationMethodForgetPassword(
	ctx context.Context,
	accountSession *utils.AccountVerificationSession,
	serviceName string,
) (*authv1.AccountVerificationResponse, error) {
	newSession := rand.Text()
	if accountSession.TwoFactor {
		s.cfg.Logger.WarnContext(
			ctx,
			"From Forget password two factor cannot be enabled",
			"service",
			serviceName,
			"userID",
			accountSession.UserID,
		)
		s.deleteAccountVerificationSession(ctx, accountSession.Key, serviceName)
		return nil, errs.ErrSessionExpired
	}
	if emailErr := s.emailForgetPassword(
		ctx,
		newSession,
		accountSession.UserID,
		accountSession.Email,
		serviceName,
	); emailErr != nil {
		return nil, emailErr
	}
	if verifyEmailErr := s.verifyEmail(ctx, accountSession.UserID, serviceName); verifyEmailErr != nil {
		return nil, verifyEmailErr
	}

	s.deleteAccountVerificationSession(ctx, accountSession.Key, serviceName)
	return &authv1.AccountVerificationResponse{
		Response: &authv1.AccountVerificationResponse_ResetSession{
			ResetSession: newSession,
		},
	}, nil
}

func (s *AuthService) accountVerificationMethodLogin(
	ctx context.Context,
	accountSession *utils.AccountVerificationSession,
	serviceName string,
) (*authv1.AccountVerificationResponse, error) {
	newSession := rand.Text()
	if accountSession.TwoFactor {
		if tfSessionErr := s.twoFactorSession(
			ctx,
			newSession,
			accountSession.UserID,
			accountSession.Role,
			serviceName,
		); tfSessionErr != nil {
			return nil, tfSessionErr
		}

		if verifyEmailErr := s.verifyEmail(ctx, accountSession.UserID, serviceName); verifyEmailErr != nil {
			return nil, verifyEmailErr
		}
		s.deleteAccountVerificationSession(ctx, accountSession.Key, serviceName)
		return &authv1.AccountVerificationResponse{
			Response: &authv1.AccountVerificationResponse_TotpSession{
				TotpSession: newSession,
			},
		}, nil
	}

	return s.accountVerificationLogin(
		ctx,
		accountSession.UserID,
		accountSession.Role,
		serviceName,
		accountSession.Key,
	)
}

func (s *AuthService) accountVerificationSessionCheck(
	ctx context.Context,
	session string,
	serviceName string,
) (*utils.AccountVerificationSession, error) {
	sessionResult, sessionResultErr := s.cfg.RateLimiter.AccountVerification.Allow(ctx, session)
	if sessionErr := LimiterCheck(
		ctx,
		&sessionResult,
		sessionResultErr,
		serviceName,
		session,
		s.cfg.Logger,
	); sessionErr != nil {
		return nil, sessionErr
	}

	accountSession, accountSessionErr := redis.HGet[utils.AccountVerificationSession](
		ctx,
		utils.AccountVerificationSessionPrefix,
		session,
		s.cfg.Client,
	)
	if accountSessionErr != nil {
		if om.IsRecordNotFound(accountSessionErr) {
			s.cfg.Logger.WarnContext(ctx, "Session not found", "service", serviceName, "session", session)
			return nil, errs.ErrSessionExpired
		}
		s.cfg.Logger.ErrorContext(ctx, "Valkey get", "service", serviceName, "error", accountSessionErr)
		return nil, errs.ErrInternalServer
	}

	userIDResult, userIDResultErr := s.cfg.RateLimiter.AccountVerificationUserID.Allow(ctx, accountSession.UserID)
	if userIDLimiterErr := LimiterCheck(
		ctx,
		&userIDResult,
		userIDResultErr,
		serviceName,
		session,
		s.cfg.Logger,
	); userIDLimiterErr != nil {
		return nil, userIDLimiterErr
	}

	return accountSession, nil
}
