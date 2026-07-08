//go:build integration

package service_test

import (
	"crypto/rand"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"neupaneanish.com.np/authentication/internal/errs"
	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
	"neupaneanish.com.np/authentication/internal/utils"
)

func TestVerifyTwoFactor(t *testing.T) {
	t.Parallel()

	t.Run("Limiter", func(t *testing.T) {
		t.Parallel()
		ctx, _ := seedVerificationGatewaySecurity(t, "12345678", utils.TwoFactorSessionPrefix)
		req := &gatewayAuthenticationv1.VerifyTwoFactorRequest{
			Session: rand.Text(),
			Code:    "A1B2C3D4",
		}

		for i := range 6 {
			response, responseErr := gatewayAuthenticationServiceClient.VerifyTwoFactor(ctx, req)
			require.Error(t, responseErr)
			assert.Nil(t, response)
			if i < 5 {
				assert.Equal(t, errs.ErrSessionExpired, responseErr)
			} else {
				assert.Equal(t, errs.ErrTooManyRequest, responseErr)
			}
		}
	})

	t.Run("Valkey Record Not Found", func(t *testing.T) {
		t.Parallel()
		md := metadata.Pairs(
			"x-user-id", uuid.NewString(),
			"x-role", "test",
			"x-jti", uuid.NewString(),
		)

		ctx := metadata.NewOutgoingContext(t.Context(), md)
		req := &gatewayAuthenticationv1.VerifyTwoFactorRequest{
			Session: rand.Text(),
			Code:    "A1B2C3D4",
		}
		response, responseErr := gatewayAuthenticationServiceClient.VerifyTwoFactor(ctx, req)
		require.Error(t, responseErr)
		assert.Nil(t, response)
		assert.Equal(t, errs.ErrSessionExpired, responseErr)
	})

	t.Run("Invalid Code", func(t *testing.T) {
		t.Parallel()
		code := "A1B2C3D4"
		ctx, session := seedVerificationGatewaySecurity(t, code, utils.TwoFactorSessionPrefix)
		req := &gatewayAuthenticationv1.VerifyTwoFactorRequest{
			Session: session,
			Code:    "123456AB",
		}

		response, responseErr := gatewayAuthenticationServiceClient.VerifyTwoFactor(ctx, req)
		require.Error(t, responseErr)
		assert.Nil(t, response)
		assert.Equal(t, errs.ErrInvalidCode, responseErr)
	})

	t.Run("Valid", func(t *testing.T) {
		t.Parallel()
		code := "A1B2C3D4"
		ctx, session := seedVerificationGatewaySecurity(t, code, utils.TwoFactorSessionPrefix)
		req := &gatewayAuthenticationv1.VerifyTwoFactorRequest{
			Session: session,
			Code:    code,
		}

		response, responseErr := gatewayAuthenticationServiceClient.VerifyTwoFactor(ctx, req)
		require.NoError(t, responseErr)
		assert.NotNil(t, response)
		assert.NotEmpty(t, response.GetSession())
	})
}
