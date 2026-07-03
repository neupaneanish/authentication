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
	"neupaneanish.com.np/authentication/internal/errs"
	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/internal/utils"
)

func TestVerifyChangePassword(t *testing.T) {
	t.Parallel()

	t.Run("Limiter", func(t *testing.T) {
		t.Parallel()
		ctx, session := seedVerificationGatewaySecurity(t, "12345678", utils.ChangePasswordSessionPrefix)
		req := &gatewayAuthenticationv1.VerifyChangePasswordRequest{
			Session: session,
			Code:    "A1B2C3D4",
		}

		for i := range 6 {
			response, responseErr := gatewayAuthenticationServiceClient.VerifyChangePassword(ctx, req)
			require.Error(t, responseErr)
			assert.Nil(t, response)
			if i < 5 {
				assert.Equal(t, errs.ErrInvalidCode, responseErr)
			} else {
				assert.Equal(t, errs.ErrTooManyRequest, responseErr)
			}
		}
	})

	t.Run("Valid", func(t *testing.T) {
		t.Parallel()
		code := "A1B2C3D4"
		ctx, session := seedVerificationGatewaySecurity(t, code, utils.ChangePasswordSessionPrefix)
		req := &gatewayAuthenticationv1.VerifyChangePasswordRequest{
			Session: session,
			Code:    code,
		}

		response, responseErr := gatewayAuthenticationServiceClient.VerifyChangePassword(ctx, req)
		require.NoError(t, responseErr)
		assert.NotNil(t, response)
		assert.NotEmpty(t, response.GetSession())
	})
}

func seedVerificationGatewaySecurity(t *testing.T, code string, prefix string) (context.Context, string) {
	t.Helper()

	userID := uuid.NewString()
	session := rand.Text()
	email := cfg.Domain.GenerateEmail(session)

	data := &utils.GatewaySecuritySession{
		Key:     userID,
		ExAt:    time.Now().Add(utils.SessionExpiry),
		Code:    code,
		Email:   email,
		Session: session,
	}
	md := metadata.Pairs(
		"x-user-id", userID,
		"x-role", "test",
		"x-jti", uuid.NewString(),
	)

	ctx := metadata.NewOutgoingContext(t.Context(), md)

	hSetErr := redis.HSet[utils.GatewaySecuritySession](
		ctx,
		prefix,
		data,
		cfg.Client,
	)
	require.NoError(t, hSetErr)

	return ctx, session
}
