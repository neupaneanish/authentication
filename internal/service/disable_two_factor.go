package service

import (
	"context"

	"neupaneanish.com.np/authentication/internal/enum"
	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
)

func (s *GatewayAuthenticationService) DeleteTwoFactor(
	ctx context.Context,
	req *gatewayAuthenticationv1.DeleteTwoFactorRequest,
) (*gatewayAuthenticationv1.DeleteTwoFactorResponse, error) {
	session, sessionErr := s.gatewayCheckPassword(
		ctx,
		"DisableTwoFactor",
		req.GetPassword().GetValue(),
		enum.DisableTwoFactor,
	)
	if sessionErr != nil {
		return nil, sessionErr
	}

	return &gatewayAuthenticationv1.DeleteTwoFactorResponse{
		Session: session,
	}, nil
}
