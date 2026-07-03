package service

import (
	"context"
	"crypto/rand"
	"time"

	"neupaneanish.com.np/authentication/internal/enum"
	"neupaneanish.com.np/authentication/internal/errs"
	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/internal/utils"
)

func (s *GatewayAuthenticationService) VerifyChangePassword(
	ctx context.Context,
	req *gatewayAuthenticationv1.VerifyChangePasswordRequest,
) (*gatewayAuthenticationv1.VerifyChangePasswordResponse, error) {
	serviceName := "VerifyChangePassword"

	securitySession, sessionErr := s.gatewaySecuritySessionVerify(
		ctx,
		serviceName,
		enum.ChangePassword,
		req.GetSession(),
	)
	if sessionErr != nil {
		return nil, sessionErr
	}

	if securitySession.Code != req.GetCode() {
		s.cfg.Logger.WarnContext(ctx, "Invalid code", "service", serviceName)
		return nil, errs.ErrInvalidCode
	}
	s.deleteGatewaySecuritySession(ctx, utils.ChangePasswordSessionPrefix, securitySession.Key, serviceName)

	session := rand.Text()

	data := &utils.GatewaySecurityVerificationChangePasswordSession{
		Key:     securitySession.Key,
		ExAt:    time.Now().Add(utils.SessionExpiry),
		Session: session,
		Email:   securitySession.Email,
	}

	if hSetErr := redis.HSet[utils.GatewaySecurityVerificationChangePasswordSession](
		ctx,
		utils.VerifyChangePasswordSessionPrefix,
		data,
		s.cfg.Client,
	); hSetErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "Valkey set", "service", serviceName, "error", hSetErr)
		return nil, errs.ErrInternalServer
	}

	return &gatewayAuthenticationv1.VerifyChangePasswordResponse{Session: session}, nil
}
