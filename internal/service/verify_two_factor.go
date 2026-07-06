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

func (s *GatewayAuthenticationService) VerifyTwoFactor(
	ctx context.Context,
	req *gatewayAuthenticationv1.VerifyTwoFactorRequest,
) (*gatewayAuthenticationv1.VerifyTwoFactorResponse, error) {
	serviceName := "VerifyTwoFactor"
	securitySession, sessionErr := s.gatewaySecuritySessionVerify(
		ctx,
		serviceName,
		enum.TwoFactor,
		req.GetSession(),
	)
	if sessionErr != nil {
		return nil, sessionErr
	}

	if securitySession.Code != req.GetCode() {
		s.cfg.Logger.WarnContext(ctx, "Invalid code", "service", serviceName)
		return nil, errs.ErrInvalidCode
	}
	s.deleteGatewaySecuritySession(ctx, utils.TwoFactorSessionPrefix, securitySession.Key, serviceName)

	tf, tfErr := s.cfg.TwoFactor.Generate(securitySession.Email)
	if tfErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "Two Factor Generate", "service", serviceName, "error", tfErr)
		return nil, errs.ErrInternalServer
	}

	session := rand.Text()
	data := &utils.GatewaySecurityVerificationTwoFactorSession{
		Key:     securitySession.Key,
		ExAt:    time.Now().Add(utils.SessionExpiry),
		Session: session,
		Email:   securitySession.Email,
		Secret:  tf.Encrypt,
	}
	if hSetErr := redis.HSet[utils.GatewaySecurityVerificationTwoFactorSession](
		ctx,
		utils.VerifyTwoFactorSessionPrefix,
		data,
		s.cfg.Client,
	); hSetErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "Valkey set", "service", serviceName, "error", hSetErr)
		return nil, errs.ErrInternalServer
	}
	return &gatewayAuthenticationv1.VerifyTwoFactorResponse{
		Session: session,
		Key:     tf.Secret,
		Uri:     tf.URL,
	}, nil
}
