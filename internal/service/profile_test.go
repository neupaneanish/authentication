//go:build integration

package service_test

import (
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"neupaneanish.com.np/authentication/internal/errs"

	"neupaneanish.com.np/authentication/internal/enum"
	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
)

func TestProfile(t *testing.T) {
	t.Parallel()

	t.Run("No User", func(t *testing.T) {
		t.Parallel()
		ctx := contextWithValue(t, uuid.NewV7(), enum.UserRoleUser)

		req := &gatewayAuthenticationv1.ProfileRequest{}
		res, err := gatewayAuthenticationServiceClient.Profile(ctx, req)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrUnauthenticated, err)
	})

	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		email := cfg.Domain.GenerateEmail(uuid.NewV7().String())
		userID, userIDErr := seedUser(
			t.Context(),
			email,
			"Password@123456",
			enum.UserStatusActive,
			true,
			enum.UserRoleUser,
		)
		require.NoError(t, userIDErr)

		ctx := contextWithValue(t, userID, enum.UserRoleUser)

		req := &gatewayAuthenticationv1.ProfileRequest{}
		res, err := gatewayAuthenticationServiceClient.Profile(ctx, req)

		require.NoError(t, err)
		assert.NotNil(t, res)
		assert.Equal(t, email, res.GetEmail())
	})
}
