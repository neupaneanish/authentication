package service

import (
	"context"

	"github.com/valkey-io/valkey-go/om"
	"google.golang.org/protobuf/types/known/timestamppb"
	"neupaneanish.com.np/authentication/internal/errs"
	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"
	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/internal/utils"
)

func (s *ExternalAuthenticationService) Refresh(
	ctx context.Context,
	req *externalAuthenticationv1.RefreshRequest,
) (*externalAuthenticationv1.RefreshResponse, error) {
	serviceName := "Refresh"
	refresh := req.GetRefresh()

	resultRefresh, resultRefreshErr := s.cfg.RateLimiter.Refresh.Allow(ctx, refresh)
	refreshSessionErr := LimiterCheck(ctx, &resultRefresh, resultRefreshErr, serviceName, refresh, s.cfg.Logger)
	if refreshSessionErr != nil {
		return nil, refreshSessionErr
	}

	userData, userDataErr := redis.HGet[utils.LoginRefreshSession](
		ctx,
		utils.LoginRefreshSessionPrefix,
		refresh,
		s.cfg.Client,
	)
	if userDataErr != nil {
		if om.IsRecordNotFound(userDataErr) {
			s.cfg.Logger.WarnContext(ctx, "Refresh Token Expired", "service", serviceName)
			return nil, errs.ErrSessionExpired
		}
		s.cfg.Logger.ErrorContext(ctx, "Valkey", "service", serviceName, "error", userDataErr)
		return nil, errs.ErrInternalServer
	}

	resultRefreshUserID, resultRefreshUserIDErr := s.cfg.RateLimiter.RefreshUserID.Allow(ctx, userData.UserID)
	limiterUserIDErr := LimiterCheck(
		ctx,
		&resultRefreshUserID,
		resultRefreshUserIDErr,
		serviceName,
		refresh,
		s.cfg.Logger,
	)
	if limiterUserIDErr != nil {
		return nil, limiterUserIDErr
	}

	if hDeleteErr := redis.HDelete[utils.LoginAccessSession](
		ctx,
		utils.LoginAccessSessionPrefix,
		userData.ID,
		s.cfg.Client,
	); hDeleteErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "Access Session delete", "service", serviceName, "error", hDeleteErr)
		return nil, errs.ErrInternalServer
	}

	if hDeleteErr := redis.HDelete[utils.LoginRefreshSession](
		ctx,
		utils.LoginRefreshSessionPrefix,
		refresh,
		s.cfg.Client,
	); hDeleteErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "Refresh Session delete", "service", serviceName, "error", hDeleteErr)
		return nil, errs.ErrInternalServer
	}

	jwt, jwtErr := s.login(ctx, userData.UserID, userData.Role, serviceName)
	if jwtErr != nil {
		return nil, jwtErr
	}

	return &externalAuthenticationv1.RefreshResponse{
		Token: &externalAuthenticationv1.Token{
			Access:   jwt.Access,
			Refresh:  jwt.Refresh,
			ExpireAt: timestamppb.New(jwt.ExpiryAt),
		},
	}, nil
}
