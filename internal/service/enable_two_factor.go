package service

import (
	"context"

	"neupaneanish.com.np/authentication/internal/enum"
	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
)

func (s *GatewayAuthenticationService) EnableTwoFactor(
	ctx context.Context,
	req *gatewayAuthenticationv1.EnableTwoFactorRequest,
) (*gatewayAuthenticationv1.EnableTwoFactorResponse, error) {
	session, sessionErr := s.gatewayCheckPassword(
		ctx,
		"EnableTwoFactor",
		req.GetPassword().GetValue(),
		enum.TwoFactor,
	)
	if sessionErr != nil {
		return nil, sessionErr
	}

	return &gatewayAuthenticationv1.EnableTwoFactorResponse{
		Session: session,
	}, nil
}
