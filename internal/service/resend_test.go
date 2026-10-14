//go:build integration

package service_test

import (
	"crypto/rand"
	"testing"
	"time"

	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"neupaneanish.com.np/authentication/internal/utils"

	"neupaneanish.com.np/authentication/internal/enum"

	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"

	"neupaneanish.com.np/authentication/internal/errs"
	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"
)

func TestResendVerification(t *testing.T) {
	t.Parallel()

	t.Run("Invalid method and verification", func(t *testing.T) {
		t.Parallel()
		session, _ := seedVerificationSession(
			t,
			uuid.NewV7(),
			"test",
			"test",
			false,
			2*time.Minute,
		)
		req := &externalAuthenticationv1.ResendRequest{Session: session}
		res, err := externalAuthenticationServiceClient.Resend(t.Context(), req)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrSessionExpired, err)
	})

	t.Run("Before Time", func(t *testing.T) {
		t.Parallel()
		session, _ := seedVerificationSession(
			t,
			uuid.NewV7(),
			enum.MethodForgetPassword,
			enum.VerificationMethodEmail,
			false,
			4*time.Minute,
		)
		req := &externalAuthenticationv1.ResendRequest{Session: session}
		res, err := externalAuthenticationServiceClient.Resend(t.Context(), req)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrResend, err)
	})

	t.Run("Rate Limiter Session", func(t *testing.T) {
		t.Parallel()
		session := rand.Text()
		req := &externalAuthenticationv1.ResendRequest{Session: session}

		for i := range 6 {
			res, err := externalAuthenticationServiceClient.Resend(t.Context(), req)
			require.Error(t, err)
			assert.Nil(t, res)
			if i < 5 {
				assert.Equal(t, errs.ErrSessionExpired, err)
			} else {
				assert.Equal(t, errs.ErrTooManyRequest, err)
			}
		}
	})

	t.Run("Rate Limiter User ID", func(t *testing.T) {
		t.Parallel()
		userID := uuid.NewV7()
		for i := range 6 {
			session, _ := seedVerificationSession(
				t,
				userID,
				enum.MethodLogin,
				enum.VerificationMethodTwoFactor,
				false,
				2*time.Minute,
			)
			req := &externalAuthenticationv1.ResendRequest{Session: session}
			res, err := externalAuthenticationServiceClient.Resend(t.Context(), req)
			require.Error(t, err)
			assert.Nil(t, res)
			if i < 5 {
				assert.Equal(t, errs.ErrSessionExpired, err)
			} else {
				assert.Equal(t, errs.ErrTooManyRequest, err)
			}
		}
	})

	t.Run("Success Login Account", func(t *testing.T) {
		t.Parallel()
		successExternalResend(t, enum.MethodLogin, enum.VerificationMethodAccount)
	})

	t.Run("Success Login Email", func(t *testing.T) {
		t.Parallel()
		successExternalResend(t, enum.MethodLogin, enum.VerificationMethodEmail)
	})

	t.Run("Success Forget Password Account", func(t *testing.T) {
		t.Parallel()
		successExternalResend(t, enum.MethodForgetPassword, enum.VerificationMethodAccount)
	})

	t.Run("Success Forget Password Email", func(t *testing.T) {
		t.Parallel()
		successExternalResend(t, enum.MethodForgetPassword, enum.VerificationMethodEmail)
	})

	t.Run("Success Forget Password Reset", func(t *testing.T) {
		t.Parallel()
		successExternalResend(t, enum.MethodForgetPassword, enum.VerificationMethodReset)
	})
}

func TestResendPasswordVerification(t *testing.T) {
	t.Parallel()

	t.Run("Rate Limit Session", func(t *testing.T) {
		t.Parallel()

		session := rand.Text()

		ctx := contextWithValue(t, uuid.NewV7(), enum.UserRoleUser)

		req := &gatewayAuthenticationv1.ResendRequest{Session: session}

		for i := range 6 {
			res, err := gatewayAuthenticationServiceClient.Resend(ctx, req)
			require.Error(t, err)
			assert.Nil(t, res)
			if i < 5 {
				assert.Equal(t, errs.ErrSessionExpired, err)
			} else {
				assert.Equal(t, errs.ErrTooManyRequest, err)
			}
		}
	})

	t.Run("Rate Limit UserID", func(t *testing.T) {
		t.Parallel()

		ctx, _, _ := seedPasswordSessionVerification(
			t,
			uuid.NewV7(),
			enum.SecurityMethodChangePassword,
			utils.SessionExpiry,
		)
		req := &gatewayAuthenticationv1.ResendRequest{Session: rand.Text()}

		for i := range 6 {
			res, err := gatewayAuthenticationServiceClient.Resend(ctx, req)
			require.Error(t, err)
			assert.Nil(t, res)
			if i < 5 {
				assert.Equal(t, errs.ErrUnauthenticated, err)
			} else {
				assert.Equal(t, errs.ErrTooManyRequest, err)
			}
		}
	})

	t.Run("Session not found", func(t *testing.T) {
		t.Parallel()

		session := rand.Text()
		ctx := contextWithValue(t, uuid.NewV7(), enum.UserRoleUser)

		req := &gatewayAuthenticationv1.ResendRequest{Session: session}
		res, err := gatewayAuthenticationServiceClient.Resend(ctx, req)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrSessionExpired, err)
	})

	t.Run("Resend on Disable Two Factor", func(t *testing.T) {
		t.Parallel()

		ctx, session, _ := seedPasswordSessionVerification(
			t,
			uuid.NewV7(),
			enum.SecurityMethodDisableTwoFactor,
			utils.SessionExpiry,
		)

		req := &gatewayAuthenticationv1.ResendRequest{Session: session}
		res, err := gatewayAuthenticationServiceClient.Resend(ctx, req)

		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrUnauthenticated, err)
	})

	t.Run("Invalid Method", func(t *testing.T) {
		t.Parallel()

		ctx, session, _ := seedPasswordSessionVerification(t, uuid.NewV7(), "test", utils.SessionExpiry)

		req := &gatewayAuthenticationv1.ResendRequest{Session: session}
		res, err := gatewayAuthenticationServiceClient.Resend(ctx, req)

		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrUnauthenticated, err)
	})

	t.Run("Success Change Password", func(t *testing.T) {
		t.Parallel()

		ctx, session, _ := seedPasswordSessionVerification(
			t,
			uuid.NewV7(),
			enum.SecurityMethodChangePassword,
			2*time.Minute,
		)

		req := &gatewayAuthenticationv1.ResendRequest{Session: session}
		res, err := gatewayAuthenticationServiceClient.Resend(ctx, req)

		require.NoError(t, err)
		assert.NotNil(t, res)
		assert.NotEmpty(t, res.GetSession())
	})

	t.Run("Before Time", func(t *testing.T) {
		t.Parallel()
		ctx, session, _ := seedPasswordSessionVerification(
			t,
			uuid.NewV7(),
			enum.SecurityMethodEnableTwoFactor,
			5*time.Minute,
		)

		req := &gatewayAuthenticationv1.ResendRequest{Session: session}
		res, err := gatewayAuthenticationServiceClient.Resend(ctx, req)

		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrResend, err)
	})

	t.Run("Success Two Factor", func(t *testing.T) {
		t.Parallel()

		ctx, session, _ := seedPasswordSessionVerification(
			t,
			uuid.NewV7(),
			enum.SecurityMethodEnableTwoFactor,
			2*time.Minute,
		)

		req := &gatewayAuthenticationv1.ResendRequest{Session: session}
		res, err := gatewayAuthenticationServiceClient.Resend(ctx, req)

		require.NoError(t, err)
		assert.NotNil(t, res)
		assert.NotEmpty(t, res.GetSession())
	})
}

func successExternalResend(
	t *testing.T,
	method enum.Method,
	verificationMethod enum.VerificationMethod,
) {
	t.Helper()
	session, _ := seedVerificationSession(t, uuid.NewV7(), method, verificationMethod, false, 2*time.Minute)
	req := &externalAuthenticationv1.ResendRequest{Session: session}
	res, err := externalAuthenticationServiceClient.Resend(t.Context(), req)
	require.NoError(t, err)
	assert.NotNil(t, res)
	assert.NotEmpty(t, res.GetSession())
}
