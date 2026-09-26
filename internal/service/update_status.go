package service

import (
	"context"

	rootAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/root/authentication/v1"
)

func (s *RootAuthenticationService) UpdateStatus(
	ctx context.Context,
	req *rootAuthenticationv1.UpdateStatusRequest,
) (*rootAuthenticationv1.UpdateStatusResponse, error) {
	serviceName := "UpdateStatus"
	if err := s.updateRoleStatusUsername(
		ctx,
		req.GetId(),
		req.GetStatus(),
		serviceName,
		"status",
		req.GetUpdatedAt().AsTime(),
	); err != nil {
		return nil, err
	}

	return &rootAuthenticationv1.UpdateStatusResponse{}, nil
}
