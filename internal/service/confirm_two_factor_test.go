//go:build integration

package service_test

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"neupaneanish.com.np/authentication/internal/enum"
	"neupaneanish.com.np/authentication/internal/errs"
	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/internal/utils"
)

func TestConfirmTwoFactor(t *testing.T) {
	t.Parallel()

	t.Run("Foreign Key Violation", func(t *testing.T) {
		t.Parallel()
		userID := uuid.NewString()
		session := rand.Text()
		md := metadata.Pairs(
			"x-user-id", userID,
			"x-role", "test",
			"x-jti", uuid.NewString(),
		)

		ctx := metadata.NewOutgoingContext(t.Context(), md)

		secret := seedConfirmTwoFactorSession(t, userID, session, cfg.Domain.GenerateEmail(session))
		code, codeErr := totp.GenerateCode(secret, time.Now())
		require.NoError(t, codeErr)

		req := &gatewayAuthenticationv1.ConfirmTwoFactorRequest{
			Session: session,
			Code:    code,
		}

		response, responseErr := gatewayAuthenticationServiceClient.ConfirmTwoFactor(ctx, req)
		require.Error(t, responseErr)
		assert.Nil(t, response)
		assert.Equal(t, errs.ErrSessionExpired, responseErr)
	})

	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		ctx, session, secret, userID := seedConfirmTwoFactor(t)
		code, codeErr := totp.GenerateCode(secret, time.Now())
		require.NoError(t, codeErr)

		for i := range 2 {
			if i < 1 {
				req := &gatewayAuthenticationv1.ConfirmTwoFactorRequest{
					Session: session,
					Code:    code,
				}
				response, responseErr := gatewayAuthenticationServiceClient.ConfirmTwoFactor(ctx, req)
				require.NoError(t, responseErr)
				assert.NotNil(t, response)
				assert.Equal(t, 10, len(response.Codes))
			} else {
				newSession := rand.Text()
				newSecret := seedConfirmTwoFactorSession(t, userID, newSession, cfg.Domain.GenerateEmail(rand.Text()))
				newCode, newCodeErr := totp.GenerateCode(newSecret, time.Now())
				require.NoError(t, newCodeErr)
				req := &gatewayAuthenticationv1.ConfirmTwoFactorRequest{
					Session: newSession,
					Code:    newCode,
				}
				response, responseErr := gatewayAuthenticationServiceClient.ConfirmTwoFactor(ctx, req)
				require.Error(t, responseErr)
				assert.Nil(t, response)
				assert.Equal(t, errs.ErrAlreadyEnabled, responseErr)
			}
		}
	})

	t.Run("Rate Limiter", func(t *testing.T) {
		t.Parallel()
		userID := uuid.NewString()
		session := rand.Text()
		md := metadata.Pairs(
			"x-user-id", userID,
			"x-role", "test",
			"x-jti", uuid.NewString(),
		)

		ctx := metadata.NewOutgoingContext(t.Context(), md)

		req := &gatewayAuthenticationv1.ConfirmTwoFactorRequest{
			Session: session,
			Code:    "123456",
		}
		for i := range 6 {
			response, responseErr := gatewayAuthenticationServiceClient.ConfirmTwoFactor(ctx, req)
			require.Error(t, responseErr)
			assert.Nil(t, response)
			if i < 5 {
				assert.Equal(t, errs.ErrSessionExpired, responseErr)
			} else {
				assert.Equal(t, errs.ErrTooManyRequest, responseErr)
			}
		}
	})

	t.Run("Invalid Session", func(t *testing.T) {
		t.Parallel()

		userID := uuid.NewString()

		_ = seedConfirmTwoFactorSession(t, userID, rand.Text(), cfg.Domain.GenerateEmail(userID))

		md := metadata.Pairs(
			"x-user-id", userID,
			"x-role", "test",
			"x-jti", uuid.NewString(),
		)

		ctx := metadata.NewOutgoingContext(t.Context(), md)

		req := &gatewayAuthenticationv1.ConfirmTwoFactorRequest{
			Session: rand.Text(),
			Code:    "123456",
		}

		response, responseErr := gatewayAuthenticationServiceClient.ConfirmTwoFactor(ctx, req)
		require.Error(t, responseErr)
		assert.Nil(t, response)
		assert.Equal(t, errs.ErrSessionExpired, responseErr)
	})

	t.Run("Invalid Code", func(t *testing.T) {
		t.Parallel()

		userID := uuid.NewString()
		session := rand.Text()

		_ = seedConfirmTwoFactorSession(t, userID, session, cfg.Domain.GenerateEmail(userID))

		md := metadata.Pairs(
			"x-user-id", userID,
			"x-role", "test",
			"x-jti", uuid.NewString(),
		)

		ctx := metadata.NewOutgoingContext(t.Context(), md)

		req := &gatewayAuthenticationv1.ConfirmTwoFactorRequest{
			Session: session,
			Code:    "123456",
		}

		response, responseErr := gatewayAuthenticationServiceClient.ConfirmTwoFactor(ctx, req)
		require.Error(t, responseErr)
		assert.Nil(t, response)
		assert.Equal(t, errs.ErrInvalidCode, responseErr)
	})
}

func seedConfirmTwoFactor(t *testing.T) (context.Context, string, string, string) {
	t.Helper()
	session := rand.Text()
	email := cfg.Domain.GenerateEmail(session)

	userID, seedErr := seedUser(
		t.Context(),
		email,
		"Password@1234",
		enum.UserStatusActive,
		true,
	)
	require.NoError(t, seedErr)
	assert.NotEmpty(t, userID)

	secret := seedConfirmTwoFactorSession(t, userID, session, email)

	md := metadata.Pairs(
		"x-user-id", userID,
		"x-role", "test",
		"x-jti", uuid.NewString(),
	)
	ctx := metadata.NewOutgoingContext(t.Context(), md)
	return ctx, session, secret, userID
}

func seedConfirmTwoFactorSession(t *testing.T, userID string, session string, email string) string {
	t.Helper()

	tf, tfErr := cfg.TwoFactor.Generate(email)
	require.NoError(t, tfErr)

	data := &utils.GatewaySecurityVerificationTwoFactorSession{
		Key:     userID,
		ExAt:    time.Now().Add(utils.SessionExpiry),
		Session: session,
		Email:   email,
		Secret:  tf.Encrypt,
	}

	hSetErr := redis.HSet[utils.GatewaySecurityVerificationTwoFactorSession](
		t.Context(),
		utils.VerifyTwoFactorSessionPrefix,
		data,
		cfg.Client,
	)
	require.NoError(t, hSetErr)
	return tf.Secret
}
