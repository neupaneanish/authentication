//go:build integration

package service_test

import (
	"crypto/rand"
	"log/slog"
	"os"
	"testing"
	"time"

	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/internal/service"
	"neupaneanish.com.np/authentication/internal/utils"

	"neupaneanish.com.np/authentication/internal/enum"

	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"

	"neupaneanish.com.np/authentication/internal/errs"
	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"
)

func TestResendVerification(t *testing.T) {
	t.Parallel()

	t.Run("Rate Limiter Session", func(t *testing.T) {
		t.Parallel()
		session := rand.Text()
		req := &externalAuthenticationv1.ResendRequest{Session: session}

		for i := range 6 {
			response, responseErr := externalAuthenticationServiceClient.Resend(t.Context(), req)
			require.Error(t, responseErr)
			assert.Nil(t, response)
			if i < 5 {
				assert.Equal(t, errs.ErrSessionExpired, responseErr)
			} else {
				assert.Equal(t, errs.ErrTooManyRequest, responseErr)
			}
		}
	})

	t.Run("Rate Limiter User ID", func(t *testing.T) {
		t.Parallel()
		userID := uuid.NewV7().String()
		for i := range 6 {
			session, _ := seedVerificationSession(t, userID, enum.MethodLogin, enum.VerificationMethodTwoFactor, false)
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

		ctx := contextWithValue(t, uuid.NewV7().String())

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

		ctx, _, _ := seedPasswordSessionVerification(t, uuid.NewV7().String(), enum.SecurityMethodChangePassword)
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
		ctx := contextWithValue(t, uuid.NewV7().String())

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
			uuid.NewV7().String(),
			enum.SecurityMethodDisableTwoFactor,
		)

		req := &gatewayAuthenticationv1.ResendRequest{Session: session}
		res, err := gatewayAuthenticationServiceClient.Resend(ctx, req)

		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrUnauthenticated, err)
	})

	t.Run("Invalid Method", func(t *testing.T) {
		t.Parallel()

		ctx, session, _ := seedPasswordSessionVerification(t, uuid.NewV7().String(), "test")

		req := &gatewayAuthenticationv1.ResendRequest{Session: session}
		res, err := gatewayAuthenticationServiceClient.Resend(ctx, req)

		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrUnauthenticated, err)
	})

	t.Run("Success Change Password", func(t *testing.T) {
		t.Parallel()

		ctx, session, _ := seedPasswordSessionVerification(t, uuid.NewV7().String(), enum.SecurityMethodChangePassword)

		req := &gatewayAuthenticationv1.ResendRequest{Session: session}
		res, err := gatewayAuthenticationServiceClient.Resend(ctx, req)

		require.NoError(t, err)
		assert.NotNil(t, res)
		assert.NotEmpty(t, res.GetSession())
	})

	t.Run("Success Two Factor", func(t *testing.T) {
		t.Parallel()

		ctx, session, _ := seedPasswordSessionVerification(t, uuid.NewV7().String(), enum.SecurityMethodEnableTwoFactor)

		req := &gatewayAuthenticationv1.ResendRequest{Session: session}
		res, err := gatewayAuthenticationServiceClient.Resend(ctx, req)

		require.NoError(t, err)
		assert.NotNil(t, res)
		assert.NotEmpty(t, res.GetSession())
	})
}

func seedVerificationSession(
	t *testing.T,
	userID string,
	method enum.Method,
	verificationMethod enum.VerificationMethod,
	enabledTwoFactor bool,
) (string, string) {
	session := rand.Text()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	code, format, codeErr := service.GenerateEmailCode(t.Context(), logger)
	require.NoError(t, codeErr)

	data := &utils.VerificationSession{
		Key:                session,
		ExAt:               time.Now().Add(utils.SessionExpiry),
		UserID:             userID,
		Role:               "Test",
		Method:             string(method),
		VerificationMethod: string(verificationMethod),
		Code:               code,
		Email:              cfg.Domain.GenerateEmail(userID),
		EnabledTwoFactor:   enabledTwoFactor,
	}

	err := redis.HSet[utils.VerificationSession](
		t.Context(),
		utils.VerificationSessionPrefix,
		data,
		cfg.Client,
	)
	require.NoError(t, err)

	return session, format
}

func successExternalResend(
	t *testing.T,
	method enum.Method,
	verificationMethod enum.VerificationMethod,
) {
	t.Helper()
	userID := uuid.NewV7().String()
	session, _ := seedVerificationSession(t, userID, method, verificationMethod, false)
	req := &externalAuthenticationv1.ResendRequest{Session: session}
	res, err := externalAuthenticationServiceClient.Resend(t.Context(), req)
	require.NoError(t, err)
	assert.NotNil(t, res)
	assert.NotEmpty(t, res.GetSession())
}
