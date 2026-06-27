package service

import (
	"context"
	"crypto/rand"

	"neupaneanish.com.np/authentication/internal/enum"
	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"
)

func (s *ExternalAuthenticationService) ResendAccountVerification(
	ctx context.Context,
	req *externalAuthenticationv1.ResendAccountVerificationRequest,
) (*externalAuthenticationv1.ResendAccountVerificationResponse, error) {
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

	return &externalAuthenticationv1.ResendAccountVerificationResponse{
		Session: newSession,
	}, nil
}
