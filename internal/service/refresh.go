package service

import (
	"context"
	"time"

	"github.com/valkey-io/valkey-go/om"
	"google.golang.org/protobuf/types/known/timestamppb"

	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"

	"neupaneanish.com.np/authentication/internal/errs"
	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/internal/utils"
)

func (s *GatewayAuthenticationService) Refresh(
	ctx context.Context,
	_ *gatewayAuthenticationv1.RefreshRequest,
) (*gatewayAuthenticationv1.RefreshResponse, error) {
	serviceName := "Refresh"
	userSession := utils.UserSessionContext(ctx)

	resultRefreshUserID, resultRefreshUserIDErr := s.cfg.RateLimiter.RefreshUserID.Allow(
		ctx,
		userSession.UserID.String(),
	)
	limiterUserIDErr := LimiterCheck(
		ctx,
		&resultRefreshUserID,
		resultRefreshUserIDErr,
		serviceName,
		userSession.Session,
		s.cfg.Logger,
	)
	if limiterUserIDErr != nil {
		return nil, limiterUserIDErr
	}

	userData, userDataErr := redis.HGet[utils.Session](
		ctx,
		utils.SessionPrefix,
		userSession.Session,
		s.cfg.Client,
	)
	if userDataErr != nil {
		if om.IsRecordNotFound(userDataErr) {
			s.cfg.Logger.WarnContext(ctx, "Token Expired", "service", serviceName)
			return nil, errs.ErrInvalidTokenOrExpired
		}
		s.cfg.Logger.ErrorContext(ctx, "Valkey", "service", serviceName, "error", userDataErr)
		return nil, errs.ErrInternalServer
	}

	remainingTime := userData.ExAt.Sub(time.Now().UTC())

	if err := redis.HDelete[utils.Session](
		ctx,
		utils.SessionPrefix,
		userSession.Session,
		s.cfg.Client,
	); err != nil {
		s.cfg.Logger.ErrorContext(ctx, "Access Session delete fail", "error", err)
		return nil, errs.ErrInternalServer
	}
	if err := redis.SRem(ctx, utils.SessionPrefix+userData.UserID, userSession.Session, s.cfg.Client); err != nil {
		s.cfg.Logger.ErrorContext(ctx, "SRem Access fail", "error", err)
		return nil, errs.ErrInternalServer
	}

	if remainingTime > 10*time.Minute {
		s.cfg.Logger.WarnContext(
			ctx,
			"Refresh requested too early. Session terminated.",
			"service", serviceName,
			"remaining", remainingTime.String(),
		)
		return nil, errs.ErrUnauthenticated
	}

	token, tokenErr := login(
		ctx,
		userData.UserID,
		userData.Role,
		userData.Username,
		serviceName,
		s.cfg.Client,
		s.cfg.Logger,
	)
	if tokenErr != nil {
		return nil, tokenErr
	}

	return &gatewayAuthenticationv1.RefreshResponse{
		Session: token.Session,
		Expires: timestamppb.New(token.Expires),
	}, nil
}
