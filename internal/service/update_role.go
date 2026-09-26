package service

import (
	"context"

	rootAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/root/authentication/v1"
)

func (s *RootAuthenticationService) UpdateRole(
	ctx context.Context,
	req *rootAuthenticationv1.UpdateRoleRequest,
) (*rootAuthenticationv1.UpdateRoleResponse, error) {
	serviceName := "UpdateRole"
	if err := s.updateRoleStatusUsername(
		ctx,
		req.GetId(),
		req.GetRole(),
		serviceName,
		"role",
		req.GetUpdatedAt().AsTime(),
	); err != nil {
		return nil, err
	}
	return &rootAuthenticationv1.UpdateRoleResponse{}, nil
}
