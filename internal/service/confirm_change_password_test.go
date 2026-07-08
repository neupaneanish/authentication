//go:build integration

package service_test

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"neupaneanish.com.np/authentication/internal/enum"
	"neupaneanish.com.np/authentication/internal/errs"
	passwordv1 "neupaneanish.com.np/authentication/internal/protobuf/common/password/v1"
	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/internal/utils"
)

func TestConfirmChangePassword(t *testing.T) {
	t.Parallel()
	oldPassword := "Password@1234"
	newPassword := "Password@12345"

	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		ctx, session := confirmChangePasswordSeed(t, oldPassword)
		req := &gatewayAuthenticationv1.ConfirmChangePasswordRequest{
			Session:         session,
			Password:        &passwordv1.Password{Value: newPassword},
			ConfirmPassword: &passwordv1.Password{Value: newPassword},
		}

		response, responseErr := gatewayAuthenticationServiceClient.ConfirmChangePassword(ctx, req)
		require.NoError(t, responseErr)
		assert.NotNil(t, response)
	})

	t.Run("Invalid Session", func(t *testing.T) {
		t.Parallel()
		ctx, _ := confirmChangePasswordSeed(t, oldPassword)
		req := &gatewayAuthenticationv1.ConfirmChangePasswordRequest{
			Session:         rand.Text(),
			Password:        &passwordv1.Password{Value: newPassword},
			ConfirmPassword: &passwordv1.Password{Value: newPassword},
		}

		response, responseErr := gatewayAuthenticationServiceClient.ConfirmChangePassword(ctx, req)
		require.Error(t, responseErr)
		assert.Nil(t, response)
		assert.Equal(t, errs.ErrSessionExpired, responseErr)
	})

	t.Run("Rate Limiter", func(t *testing.T) {
		t.Parallel()

		md := metadata.Pairs(
			"x-user-id", uuid.NewString(),
			"x-role", "test",
			"x-jti", uuid.NewString(),
		)
		ctx := metadata.NewOutgoingContext(t.Context(), md)
		req := &gatewayAuthenticationv1.ConfirmChangePasswordRequest{
			Session:         rand.Text(),
			Password:        &passwordv1.Password{Value: newPassword},
			ConfirmPassword: &passwordv1.Password{Value: newPassword},
		}

		for i := range 6 {
			response, responseErr := gatewayAuthenticationServiceClient.ConfirmChangePassword(ctx, req)
			require.Error(t, responseErr)
			assert.Nil(t, response)
			if i < 5 {
				assert.Equal(t, errs.ErrSessionExpired, responseErr)
			} else {
				assert.Equal(t, errs.ErrTooManyRequest, responseErr)
			}
		}
	})

	t.Run("No User in DB", func(t *testing.T) {
		t.Parallel()
		userID := uuid.NewString()
		session := rand.Text()
		seedConfirmChangePasswordSession(t, userID, session, cfg.Domain.GenerateEmail(session))
		md := metadata.Pairs(
			"x-user-id", userID,
			"x-role", "test",
			"x-jti", uuid.NewString(),
		)
		ctx := metadata.NewOutgoingContext(t.Context(), md)
		req := &gatewayAuthenticationv1.ConfirmChangePasswordRequest{
			Session:         rand.Text(),
			Password:        &passwordv1.Password{Value: newPassword},
			ConfirmPassword: &passwordv1.Password{Value: newPassword},
		}
		response, responseErr := gatewayAuthenticationServiceClient.ConfirmChangePassword(ctx, req)
		require.Error(t, responseErr)
		assert.Nil(t, response)
		assert.Equal(t, errs.ErrSessionExpired, responseErr)
	})

	t.Run("Previous Password", func(t *testing.T) {
		t.Parallel()
		ctx, session := confirmChangePasswordSeed(t, oldPassword)
		req := &gatewayAuthenticationv1.ConfirmChangePasswordRequest{
			Session:         session,
			Password:        &passwordv1.Password{Value: oldPassword},
			ConfirmPassword: &passwordv1.Password{Value: oldPassword},
		}

		response, responseErr := gatewayAuthenticationServiceClient.ConfirmChangePassword(ctx, req)
		require.Error(t, responseErr)
		assert.Nil(t, response)
		assert.Equal(t, errs.ErrPreviousPassword, responseErr)
	})
}

func confirmChangePasswordSeed(t *testing.T, rawPassword string) (context.Context, string) {
	t.Helper()
	session := rand.Text()
	email := cfg.Domain.GenerateEmail(session)

	userID, seedErr := seedUser(
		t.Context(),
		email,
		rawPassword,
		enum.UserStatusActive,
		true,
	)
	require.NoError(t, seedErr)
	assert.NotEmpty(t, userID)

	seedConfirmChangePasswordSession(t, userID, session, email)

	md := metadata.Pairs(
		"x-user-id", userID,
		"x-role", "test",
		"x-jti", uuid.NewString(),
	)
	ctx := metadata.NewOutgoingContext(t.Context(), md)
	return ctx, session
}

func seedConfirmChangePasswordSession(t *testing.T, userID string, session string, email string) {
	t.Helper()
	data := &utils.GatewaySecurityVerificationChangePasswordSession{
		Key:     userID,
		ExAt:    time.Now().Add(utils.SessionExpiry),
		Session: session,
		Email:   email,
	}

	hSetErr := redis.HSet[utils.GatewaySecurityVerificationChangePasswordSession](
		t.Context(),
		utils.VerifyChangePasswordSessionPrefix,
		data,
		cfg.Client,
	)
	require.NoError(t, hSetErr)
}
