//go:build integration

package service_test

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"neupaneanish.com.np/authentication/internal/enum"
	"neupaneanish.com.np/authentication/internal/errs"
	passwordv1 "neupaneanish.com.np/authentication/internal/protobuf/common/password/v1"
	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/internal/utils"
)

func TestChangePassword(t *testing.T) {
	t.Parallel()
	oldPassword := "Password@1234"
	newPassword := "Password@12345"

	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		ctx, session := changePasswordSeed(t, oldPassword)
		req := &gatewayAuthenticationv1.ChangePasswordRequest{
			Session:         session,
			Password:        &passwordv1.Password{Value: newPassword},
			ConfirmPassword: &passwordv1.Password{Value: newPassword},
		}

		response, responseErr := gatewayAuthenticationServiceClient.ChangePassword(ctx, req)
		require.NoError(t, responseErr)
		assert.NotNil(t, response)
	})

	t.Run("Invalid Session", func(t *testing.T) {
		t.Parallel()
		ctx, _ := changePasswordSeed(t, oldPassword)
		req := &gatewayAuthenticationv1.ChangePasswordRequest{
			Session:         rand.Text(),
			Password:        &passwordv1.Password{Value: newPassword},
			ConfirmPassword: &passwordv1.Password{Value: newPassword},
		}

		response, responseErr := gatewayAuthenticationServiceClient.ChangePassword(ctx, req)
		require.Error(t, responseErr)
		assert.Nil(t, response)
		assert.Equal(t, errs.ErrSessionExpired, responseErr)
	})

	t.Run("Rate Limiter", func(t *testing.T) {
		t.Parallel()

		ctx := contextWithValue(t, uuid.NewV7().String())
		req := &gatewayAuthenticationv1.ChangePasswordRequest{
			Session:         rand.Text(),
			Password:        &passwordv1.Password{Value: newPassword},
			ConfirmPassword: &passwordv1.Password{Value: newPassword},
		}

		for i := range 6 {
			response, responseErr := gatewayAuthenticationServiceClient.ChangePassword(ctx, req)
			require.Error(t, responseErr)
			assert.Nil(t, response)
			if i < 6 {
				assert.Equal(t, errs.ErrSessionExpired, responseErr)
			} else {
				assert.Equal(t, errs.ErrTooManyRequest, responseErr)
			}
		}
	})

	t.Run("No User in DB", func(t *testing.T) {
		t.Parallel()
		userID := uuid.NewV7().String()
		session := rand.Text()
		seedChangePasswordSession(t, userID, session, cfg.Domain.GenerateEmail(session))

		ctx := contextWithValue(t, userID)
		req := &gatewayAuthenticationv1.ChangePasswordRequest{
			Session:         rand.Text(),
			Password:        &passwordv1.Password{Value: newPassword},
			ConfirmPassword: &passwordv1.Password{Value: newPassword},
		}
		response, responseErr := gatewayAuthenticationServiceClient.ChangePassword(ctx, req)
		require.Error(t, responseErr)
		assert.Nil(t, response)
		assert.Equal(t, errs.ErrSessionExpired, responseErr)
	})

	t.Run("Previous Password", func(t *testing.T) {
		t.Parallel()
		ctx, session := changePasswordSeed(t, oldPassword)
		req := &gatewayAuthenticationv1.ChangePasswordRequest{
			Session:         session,
			Password:        &passwordv1.Password{Value: oldPassword},
			ConfirmPassword: &passwordv1.Password{Value: oldPassword},
		}

		response, responseErr := gatewayAuthenticationServiceClient.ChangePassword(ctx, req)
		require.Error(t, responseErr)
		assert.Nil(t, response)
		assert.Equal(t, errs.ErrPreviousPassword, responseErr)
	})
}

func changePasswordSeed(t *testing.T, rawPassword string) (context.Context, string) {
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

	seedChangePasswordSession(t, userID, session, email)

	ctx := contextWithValue(t, userID)
	return ctx, session
}

func seedChangePasswordSession(t *testing.T, userID string, session string, email string) {
	t.Helper()
	data := &utils.ChangePasswordSession{
		Key:     userID,
		ExAt:    time.Now().Add(utils.SessionExpiry),
		Session: session,
		Email:   email,
	}

	hSetErr := redis.HSet[utils.ChangePasswordSession](
		t.Context(),
		utils.ChangePasswordSessionPrefix,
		data,
		cfg.Client,
	)
	require.NoError(t, hSetErr)
}
