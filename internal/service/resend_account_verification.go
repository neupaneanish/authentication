package service

import (
	"context"
	"crypto/rand"

	"neupaneanish.com.np/api/internal/enum"
	authv1 "neupaneanish.com.np/api/internal/protobuf/auth/v1"
)

func (s *AuthService) ResendAccountVerification(
	ctx context.Context,
	req *authv1.ResendAccountVerificationRequest,
) (*authv1.ResendAccountVerificationResponse, error) {
	serviceName := "ResendAccountVerification"
	session := req.GetSession()

	accountSession, accountSessionErr := s.accountVerificationSessionCheck(ctx, session, serviceName)
	if accountSessionErr != nil {
		return nil, accountSessionErr
	}

	newSession := rand.Text()

	if emailVerificationErr := s.emailVerification(
		ctx,
		serviceName,
		enum.Method(accountSession.Method),
		newSession,
		accountSession.UserID,
		accountSession.Role,
		accountSession.TwoFactor,
		accountSession.Account,
		accountSession.Email,
	); emailVerificationErr != nil {
		return nil, emailVerificationErr
	}

	s.deleteAccountVerificationSession(ctx, session, serviceName)

	return &authv1.ResendAccountVerificationResponse{
		Session: newSession,
	}, nil
}
