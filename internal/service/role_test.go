//go:build integration

package service_test

import (
	"crypto/rand"
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"neupaneanish.com.np/authentication/internal/enum"

	"neupaneanish.com.np/authentication/internal/errs"
	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
)

func TestRole(t *testing.T) {
	t.Parallel()

	t.Run("No Context", func(t *testing.T) {
		t.Parallel()

		req := &gatewayAuthenticationv1.RoleRequest{}
		res, err := gatewayAuthenticationServiceClient.Role(t.Context(), req)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrUnauthenticated, err)
	})

	t.Run("Invalid Role and Invalid User ID", func(t *testing.T) {
		t.Parallel()

		md := metadata.Pairs(
			"x-user-id", rand.Text(),
			"x-role", "test",
			"x-jti", uuid.NewV7().String(),
		)

		ctx := metadata.NewOutgoingContext(t.Context(), md)

		req := &gatewayAuthenticationv1.RoleRequest{}
		res, err := gatewayAuthenticationServiceClient.Role(ctx, req)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrUnauthenticated, err)
	})

	t.Run("No User", func(t *testing.T) {
		t.Parallel()

		ctx := contextWithValue(t, uuid.NewV7(), enum.UserRoleUser)

		req := &gatewayAuthenticationv1.RoleRequest{}
		res, err := gatewayAuthenticationServiceClient.Role(ctx, req)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrUnauthenticated, err)
	})

	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		userID, userIDErr := seedUser(
			t.Context(),
			cfg.Domain.GenerateEmail(uuid.NewV7().String()),
			"Password@123456",
			enum.UserStatusActive,
			true,
			enum.UserRoleUser,
		)
		require.NoError(t, userIDErr)

		ctx := contextWithValue(t, userID, enum.UserRoleUser)

		req := &gatewayAuthenticationv1.RoleRequest{}
		res, err := gatewayAuthenticationServiceClient.Role(ctx, req)

		require.NoError(t, err)
		assert.NotNil(t, res)
		assert.Equal(t, enum.UserRoleUser, enum.UserRole(res.GetRole()))
	})
}
