//go:build integration

package service_test

import (
	"testing"

	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"neupaneanish.com.np/authentication/internal/enum"

	"neupaneanish.com.np/authentication/internal/errs"
	passwordv1 "neupaneanish.com.np/authentication/internal/protobuf/common/password/v1"
	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
)

func TestPasswordVerification(t *testing.T) {
	t.Parallel()

	t.Run("No User", func(t *testing.T) {
		t.Parallel()

		ctx := contextWithValue(t, uuid.NewV7(), enum.UserRoleUser)

		req := &gatewayAuthenticationv1.PasswordVerificationRequest{
			Password: &passwordv1.Password{Value: "Password@12345"},
			Method:   gatewayAuthenticationv1.PasswordVerificationMethod_PASSWORD_VERIFICATION_METHOD_CHANGE,
		}
		response, responseErr := gatewayAuthenticationServiceClient.PasswordVerification(ctx, req)
		require.Error(t, responseErr)
		assert.Nil(t, response)
		assert.Equal(t, errs.ErrSessionExpired, responseErr)
	})

	t.Run("Unknown Method", func(t *testing.T) {
		t.Parallel()

		ctx := contextWithValue(t, uuid.NewV7(), enum.UserRoleUser)

		req := &gatewayAuthenticationv1.PasswordVerificationRequest{
			Password: &passwordv1.Password{Value: "Password@12345"},
			Method:   5,
		}
		response, responseErr := gatewayAuthenticationServiceClient.PasswordVerification(ctx, req)
		require.Error(t, responseErr)
		assert.Nil(t, response)
		assert.Equal(t, errs.ErrInvalidMethod, responseErr)
	})

	t.Run("Rate Limit Change", func(t *testing.T) {
		t.Parallel()
		passwordVerificationRateLimit(
			t,
			gatewayAuthenticationv1.PasswordVerificationMethod_PASSWORD_VERIFICATION_METHOD_CHANGE,
		)
	})

	t.Run("Rate Limit Enable", func(t *testing.T) {
		t.Parallel()
		passwordVerificationRateLimit(
			t,
			gatewayAuthenticationv1.PasswordVerificationMethod_PASSWORD_VERIFICATION_METHOD_ENABLED,
		)
	})

	t.Run("Rate Limit Disabled", func(t *testing.T) {
		t.Parallel()
		passwordVerificationRateLimit(
			t,
			gatewayAuthenticationv1.PasswordVerificationMethod_PASSWORD_VERIFICATION_METHOD_DISABLED,
		)
	})

	t.Run("Invalid Password", func(t *testing.T) {
		t.Parallel()
		userID, seedErr := seedUser(
			t.Context(),
			cfg.Domain.GenerateEmail(uuid.NewV7().String()),
			"Password@1234",
			enum.UserStatusActive,
			true,
			enum.UserRoleUser,
		)
		require.NoError(t, seedErr)

		ctx := contextWithValue(t, userID, enum.UserRoleUser)

		req := &gatewayAuthenticationv1.PasswordVerificationRequest{
			Password: &passwordv1.Password{Value: "Password@12345"},
			Method:   gatewayAuthenticationv1.PasswordVerificationMethod_PASSWORD_VERIFICATION_METHOD_CHANGE,
		}
		response, responseErr := gatewayAuthenticationServiceClient.PasswordVerification(ctx, req)
		require.Error(t, responseErr)
		assert.Nil(t, response)
		assert.Equal(t, errs.ErrInvalidPassword, responseErr)
	})

	t.Run("Success Change", func(t *testing.T) {
		t.Parallel()
		successPasswordVerification(
			t,
			gatewayAuthenticationv1.PasswordVerificationMethod_PASSWORD_VERIFICATION_METHOD_CHANGE,
		)
	})

	t.Run("Success Enable", func(t *testing.T) {
		t.Parallel()
		successPasswordVerification(
			t,
			gatewayAuthenticationv1.PasswordVerificationMethod_PASSWORD_VERIFICATION_METHOD_ENABLED,
		)
	})

	t.Run("Success Disabled", func(t *testing.T) {
		t.Parallel()
		successPasswordVerification(
			t,
			gatewayAuthenticationv1.PasswordVerificationMethod_PASSWORD_VERIFICATION_METHOD_DISABLED,
		)
	})
}

func passwordVerificationRateLimit(t *testing.T, method gatewayAuthenticationv1.PasswordVerificationMethod) {
	t.Helper()

	password := "Password@12345"
	userID := uuid.NewV7()

	ctx := contextWithValue(t, userID, enum.UserRoleUser)

	req := &gatewayAuthenticationv1.PasswordVerificationRequest{
		Password: &passwordv1.Password{Value: password},
		Method:   method,
	}

	for i := range 7 {
		res, err := gatewayAuthenticationServiceClient.PasswordVerification(ctx, req)
		require.Error(t, err)
		assert.Nil(t, res)

		if i < 6 {
			assert.Equal(t, errs.ErrSessionExpired, err)
		} else {
			assert.Equal(t, errs.ErrTooManyRequest, err)
		}
	}
}

func successPasswordVerification(t *testing.T, method gatewayAuthenticationv1.PasswordVerificationMethod) {
	t.Helper()
	password := "Password@12345"
	userID, seedErr := seedUser(
		t.Context(),
		cfg.Domain.GenerateEmail(uuid.NewV7().String()),
		password,
		enum.UserStatusActive,
		true,
		enum.UserRoleUser,
	)
	require.NoError(t, seedErr)

	ctx := contextWithValue(t, userID, enum.UserRoleUser)

	req := &gatewayAuthenticationv1.PasswordVerificationRequest{
		Password: &passwordv1.Password{Value: password},
		Method:   method,
	}
	response, responseErr := gatewayAuthenticationServiceClient.PasswordVerification(ctx, req)
	require.NoError(t, responseErr)
	assert.NotNil(t, response)
}
