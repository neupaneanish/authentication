//go:build integration

package service_test

import (
	"crypto/rand"
	"strings"
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
	"neupaneanish.com.np/authentication/internal/repository"
	"neupaneanish.com.np/authentication/internal/utils"
)

func TestConfirmDeleteTwoFactor(t *testing.T) {
	t.Parallel()

	t.Run("Limiter", func(t *testing.T) {
		t.Parallel()

		md := metadata.Pairs(
			"x-user-id", uuid.NewString(),
			"x-role", "test",
			"x-jti", uuid.NewString(),
		)
		ctx := metadata.NewOutgoingContext(t.Context(), md)
		req := &gatewayAuthenticationv1.ConfirmDeleteTwoFactorRequest{
			Session: rand.Text(),
			Code:    nil,
		}

		for i := range 6 {
			response, responseErr := gatewayAuthenticationServiceClient.ConfirmDeleteTwoFactor(ctx, req)
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
		ctx, _ := seedVerificationGatewaySecurity(t, "12345678", utils.DeleteTwoFactorSessionPrefix)
		req := &gatewayAuthenticationv1.ConfirmDeleteTwoFactorRequest{
			Session: rand.Text(),
			Code:    nil,
		}
		response, responseErr := gatewayAuthenticationServiceClient.ConfirmDeleteTwoFactor(ctx, req)
		require.Error(t, responseErr)
		assert.Nil(t, response)
		assert.Equal(t, errs.ErrSessionExpired, responseErr)
	})

	t.Run("Invalid One of code", func(t *testing.T) {
		t.Parallel()
		ctx, session := seedVerificationGatewaySecurity(t, "12345678", utils.DeleteTwoFactorSessionPrefix)
		req := &gatewayAuthenticationv1.ConfirmDeleteTwoFactorRequest{
			Session: session,
			Code:    nil,
		}
		response, responseErr := gatewayAuthenticationServiceClient.ConfirmDeleteTwoFactor(ctx, req)
		require.Error(t, responseErr)
		assert.Nil(t, response)
		assert.Equal(t, errs.ErrInvalidCode, responseErr)
	})

	t.Run("Invalid TOTP Code", func(t *testing.T) {
		t.Parallel()

		userID, session, _, _ := seedTwoFactorUser(t)
		ctx := contextWithValue(t, userID)
		req := &gatewayAuthenticationv1.ConfirmDeleteTwoFactorRequest{
			Session: session,
			Code:    &gatewayAuthenticationv1.ConfirmDeleteTwoFactorRequest_Totp{Totp: "123456"},
		}
		response, responseErr := gatewayAuthenticationServiceClient.ConfirmDeleteTwoFactor(ctx, req)
		require.Error(t, responseErr)
		assert.Nil(t, response)
		assert.Equal(t, errs.ErrInvalidCode, responseErr)
	})

	t.Run("Invalid Recovery Code", func(t *testing.T) {
		t.Parallel()

		userID, session, _, _ := seedTwoFactorUser(t)
		ctx := contextWithValue(t, userID)
		req := &gatewayAuthenticationv1.ConfirmDeleteTwoFactorRequest{
			Session: session,
			Code:    &gatewayAuthenticationv1.ConfirmDeleteTwoFactorRequest_Recovery{Recovery: "1234567890"},
		}
		response, responseErr := gatewayAuthenticationServiceClient.ConfirmDeleteTwoFactor(ctx, req)
		require.Error(t, responseErr)
		assert.Nil(t, response)
		assert.Equal(t, errs.ErrInvalidCode, responseErr)
	})

	t.Run("Success TOTP", func(t *testing.T) {
		t.Parallel()

		userID, session, secret, _ := seedTwoFactorUser(t)
		ctx := contextWithValue(t, userID)
		code, codeErr := totp.GenerateCode(secret, time.Now())
		require.NoError(t, codeErr)

		req := &gatewayAuthenticationv1.ConfirmDeleteTwoFactorRequest{
			Session: session,
			Code:    &gatewayAuthenticationv1.ConfirmDeleteTwoFactorRequest_Totp{Totp: code},
		}
		response, responseErr := gatewayAuthenticationServiceClient.ConfirmDeleteTwoFactor(ctx, req)
		require.NoError(t, responseErr)
		assert.NotNil(t, response)
	})

	t.Run("Success Recovery Code", func(t *testing.T) {
		t.Parallel()

		userID, session, _, recoveryCodes := seedTwoFactorUser(t)
		ctx := contextWithValue(t, userID)
		code := strings.ReplaceAll(recoveryCodes[0], "-", "")
		req := &gatewayAuthenticationv1.ConfirmDeleteTwoFactorRequest{
			Session: session,
			Code:    &gatewayAuthenticationv1.ConfirmDeleteTwoFactorRequest_Recovery{Recovery: code},
		}
		response, responseErr := gatewayAuthenticationServiceClient.ConfirmDeleteTwoFactor(ctx, req)
		require.NoError(t, responseErr)
		assert.NotNil(t, response)
	})
}

func seedTwoFactorUser(t *testing.T) (string, string, string, []string) {
	t.Helper()

	session := rand.Text()
	email := cfg.Domain.GenerateEmail(session)

	userIDStr, seedUserErr := seedUser(t.Context(), email, "Password@123456", enum.UserStatusActive, false)
	require.NoError(t, seedUserErr)

	data := &utils.GatewaySecuritySession{
		Key:     userIDStr,
		ExAt:    time.Now().Add(utils.SessionExpiry),
		Code:    "12345678",
		Email:   email,
		Session: session,
	}

	hSetErr := redis.HSet[utils.GatewaySecuritySession](
		t.Context(),
		utils.DeleteTwoFactorSessionPrefix,
		data,
		cfg.Client,
	)
	require.NoError(t, hSetErr)

	userID := uuid.MustParse(userIDStr)
	secret, secretErr := cfg.TwoFactor.Generate(email)
	require.NoError(t, secretErr)

	secretEncrypt, secretEncryptErr := cfg.TwoFactor.Encrypt(secret.Secret)
	require.NoError(t, secretEncryptErr)

	recoveryCodes, rcErr := cfg.TwoFactor.GenerateRecoveryCodes()
	require.NoError(t, rcErr)
	assert.Equal(t, len(recoveryCodes.Plain), 10)
	assert.Equal(t, len(recoveryCodes.Hash), 10)

	params := &repository.CreateTwoFactorParams{
		UserID:    userID,
		Secret:    secretEncrypt,
		CreatedBy: userID,
		UpdatedBy: userID,
	}

	recoveryCodesRows := make([]*repository.CreateRecoveryCodesParams, 0, len(recoveryCodes.Hash))
	for _, hash := range recoveryCodes.Hash {
		recoveryCodesRows = append(recoveryCodesRows, &repository.CreateRecoveryCodesParams{
			UserID:    userID,
			Code:      hash,
			CreatedBy: userID,
			UpdatedBy: userID,
		})
	}

	row, rowErr := cfg.Repository.CreateTwoFactor(t.Context(), params)
	require.NoError(t, rowErr)
	assert.GreaterOrEqual(t, row.RowsAffected(), int64(1))

	rowRecovery, rowRecoveryErr := cfg.Repository.CreateRecoveryCodes(t.Context(), recoveryCodesRows)
	require.NoError(t, rowRecoveryErr)
	assert.Equal(t, rowRecovery, int64(10))

	return userIDStr, session, secret.Secret, recoveryCodes.Plain
}
