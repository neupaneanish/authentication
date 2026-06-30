//go:build integration

package service_test

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"neupaneanish.com.np/authentication/internal/enum"
	"neupaneanish.com.np/authentication/internal/errs"
	passwordv1 "neupaneanish.com.np/authentication/internal/protobuf/common/password/v1"
	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
)

func TestChangePassword(t *testing.T) {
	t.Parallel()
	oldPassword := "Password@123"
	newPassword := "Password@1234"

	t.Run("Rate Limiter", func(t *testing.T) {
		t.Parallel()

		ctx := seedChangePassword(t, oldPassword)

		req := &gatewayAuthenticationv1.ChangePasswordRequest{
			Password: &passwordv1.Password{Value: newPassword},
		}

		for i := range 6 {
			response, responseErr := gatewayAuthenticationServiceClient.ChangePassword(ctx, req)
			require.Error(t, responseErr)
			assert.Nil(t, response)

			if i < 5 {
				assert.Equal(t, errs.ErrInvalidPassword, responseErr)
			} else {
				assert.Equal(t, errs.ErrTooManyRequest, responseErr)
			}
		}
	})

	t.Run("No User", func(t *testing.T) {
		t.Parallel()
		md := metadata.Pairs(
			"x-user-id", uuid.NewString(),
			"x-role", "test",
			"x-jti", uuid.NewString(),
		)
		ctx := metadata.NewOutgoingContext(t.Context(), md)

		req := &gatewayAuthenticationv1.ChangePasswordRequest{
			Password: &passwordv1.Password{Value: newPassword},
		}
		response, responseErr := gatewayAuthenticationServiceClient.ChangePassword(ctx, req)
		require.Error(t, responseErr)
		assert.Nil(t, response)
		assert.Equal(t, errs.ErrSessionExpired, responseErr)
	})

	t.Run("Valid Password", func(t *testing.T) {
		t.Parallel()
		ctx := seedChangePassword(t, oldPassword)

		req := &gatewayAuthenticationv1.ChangePasswordRequest{
			Password: &passwordv1.Password{Value: oldPassword},
		}
		response, responseErr := gatewayAuthenticationServiceClient.ChangePassword(ctx, req)
		require.NoError(t, responseErr)
		assert.NotNil(t, response)
		assert.NotEmpty(t, response.GetSession())
	})

	t.Run("Missing metadata", func(t *testing.T) {
		t.Parallel()
		req := &gatewayAuthenticationv1.ChangePasswordRequest{
			Password: &passwordv1.Password{Value: newPassword},
		}
		response, responseErr := gatewayAuthenticationServiceClient.ChangePassword(t.Context(), req)
		require.Error(t, responseErr)
		assert.Nil(t, response)
		assert.Equal(t, errs.ErrSessionExpired, responseErr)
	})
}

func seedChangePassword(t *testing.T, password string) context.Context {
	t.Helper()

	email := cfg.Domain.GenerateEmail(rand.Text())

	userID, userErr := seedUser(t.Context(), email, password, enum.UserStatusActive, true)
	require.NoError(t, userErr)

	md := metadata.Pairs(
		"x-user-id", userID,
		"x-role", "test",
		"x-jti", uuid.NewString(),
	)

	ctx := metadata.NewOutgoingContext(t.Context(), md)
	return ctx
}
