//go:build integration

package service_test

import (
	"context"
	"crypto/rand"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"uuid"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"neupaneanish.com.np/authentication/internal/service"

	"neupaneanish.com.np/authentication/internal/enum"

	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/internal/utils"

	"neupaneanish.com.np/authentication/internal/errs"

	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
)

func TestPasswordSessionVerification(t *testing.T) {
	t.Parallel()

	t.Run("Session Not Found", func(t *testing.T) {
		t.Parallel()

		userID := uuid.NewV7().String()

		ctx := contextWithValue(t, userID)

		req := &gatewayAuthenticationv1.PasswordSessionVerificationRequest{
			Session: rand.Text(),
			Code:    &gatewayAuthenticationv1.PasswordSessionVerificationRequest_Email{Email: "12345678"},
		}

		res, err := gatewayAuthenticationServiceClient.PasswordSessionVerification(ctx, req)

		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrSessionExpired, err)
	})

	t.Run("Rate Limiter Change", func(t *testing.T) {
		t.Parallel()
		passwordSessionVerificationRateLimiter(t, uuid.NewV7().String(), enum.SecurityMethodChangePassword, false)
	})

	t.Run("Rate Limiter Enable", func(t *testing.T) {
		t.Parallel()

		passwordSessionVerificationRateLimiter(t, uuid.NewV7().String(), enum.SecurityMethodEnableTwoFactor, false)
	})

	t.Run("Rate Limiter Disabled", func(t *testing.T) {
		t.Parallel()

		passwordSessionVerificationRateLimiter(t, uuid.NewV7().String(), enum.SecurityMethodDisableTwoFactor, false)
	})

	t.Run("Invalid Method", func(t *testing.T) {
		t.Parallel()
		ctx, session, code := seedPasswordSessionVerification(t, uuid.NewV7().String(), "Test")
		req := &gatewayAuthenticationv1.PasswordSessionVerificationRequest{
			Session: session,
			Code:    &gatewayAuthenticationv1.PasswordSessionVerificationRequest_Email{Email: code},
		}

		res, err := gatewayAuthenticationServiceClient.PasswordSessionVerification(ctx, req)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrUnauthenticated, err)
	})

	t.Run("Invalid Code for Change", func(t *testing.T) {
		t.Parallel()
		invalidCode(t, enum.SecurityMethodChangePassword)
	})

	t.Run("Invalid Code for Enable", func(t *testing.T) {
		t.Parallel()
		invalidCode(t, enum.SecurityMethodEnableTwoFactor)
	})

	t.Run("Invalid Code for Change and Enable TOTP", func(t *testing.T) {
		t.Parallel()
		ctx, session, _ := seedPasswordSessionVerification(t, uuid.NewV7().String(), enum.SecurityMethodChangePassword)
		req := &gatewayAuthenticationv1.PasswordSessionVerificationRequest{
			Session: session,
			Code:    &gatewayAuthenticationv1.PasswordSessionVerificationRequest_Totp{Totp: "123456"},
		}

		res, err := gatewayAuthenticationServiceClient.PasswordSessionVerification(ctx, req)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrUnauthenticated, err)
	})

	t.Run("Invalid Code Method for Disable", func(t *testing.T) {
		t.Parallel()
		ctx, session, _ := seedPasswordSessionVerification(
			t,
			uuid.NewV7().String(),
			enum.SecurityMethodDisableTwoFactor,
		)
		req := &gatewayAuthenticationv1.PasswordSessionVerificationRequest{
			Session: session,
			Code:    &gatewayAuthenticationv1.PasswordSessionVerificationRequest_Email{Email: "12345678"},
		}

		res, err := gatewayAuthenticationServiceClient.PasswordSessionVerification(ctx, req)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrUnauthenticated, err)
	})

	t.Run("Invalid Code for Disable TOTP", func(t *testing.T) {
		t.Parallel()

		ctx, session, _, _ := seedPasswordSessionVerificationDisable(t, false)

		req := &gatewayAuthenticationv1.PasswordSessionVerificationRequest{
			Session: session,
			Code:    &gatewayAuthenticationv1.PasswordSessionVerificationRequest_Totp{Totp: "123456"},
		}

		res, err := gatewayAuthenticationServiceClient.PasswordSessionVerification(ctx, req)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrInvalidCode, err)
	})

	t.Run("Invalid Code for Disable Recovery", func(t *testing.T) {
		t.Parallel()

		ctx, session, _, _ := seedPasswordSessionVerificationDisable(t, true)

		req := &gatewayAuthenticationv1.PasswordSessionVerificationRequest{
			Session: session,
			Code:    &gatewayAuthenticationv1.PasswordSessionVerificationRequest_Recovery{Recovery: "0123456789"},
		}

		res, err := gatewayAuthenticationServiceClient.PasswordSessionVerification(ctx, req)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrInvalidCode, err)
	})

	t.Run("Success Change", func(t *testing.T) {
		t.Parallel()

		ctx, session, code := seedPasswordSessionVerification(
			t,
			uuid.NewV7().String(),
			enum.SecurityMethodChangePassword,
		)
		req := &gatewayAuthenticationv1.PasswordSessionVerificationRequest{
			Session: session,
			Code:    &gatewayAuthenticationv1.PasswordSessionVerificationRequest_Email{Email: code},
		}

		res, err := gatewayAuthenticationServiceClient.PasswordSessionVerification(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, res)
		assert.NotEmpty(t, res.GetChangePassword())
	})

	t.Run("Success Enable", func(t *testing.T) {
		t.Parallel()

		ctx, session, code := seedSuccessEnable(t)

		req := &gatewayAuthenticationv1.PasswordSessionVerificationRequest{
			Session: session,
			Code:    &gatewayAuthenticationv1.PasswordSessionVerificationRequest_Email{Email: code},
		}

		res, err := gatewayAuthenticationServiceClient.PasswordSessionVerification(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, res)
		assert.NotEmpty(t, res.GetEnableTwoFactor().GetSession())
	})

	t.Run("Success Disabled TOTP", func(t *testing.T) {
		t.Parallel()

		ctx, session, secret, _ := seedPasswordSessionVerificationDisable(t, false)

		code, codeErr := totp.GenerateCode(secret, time.Now())
		require.NoError(t, codeErr)

		req := &gatewayAuthenticationv1.PasswordSessionVerificationRequest{
			Session: session,
			Code:    &gatewayAuthenticationv1.PasswordSessionVerificationRequest_Totp{Totp: code},
		}

		res, err := gatewayAuthenticationServiceClient.PasswordSessionVerification(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, res)
		assert.True(t, res.GetDisabledTwoFactor())
	})

	t.Run("Success Disabled Recovery", func(t *testing.T) {
		t.Parallel()

		ctx, session, _, recoveryCodes := seedPasswordSessionVerificationDisable(t, true)

		code := strings.ReplaceAll(recoveryCodes[0], "-", "")

		req := &gatewayAuthenticationv1.PasswordSessionVerificationRequest{
			Session: session,
			Code:    &gatewayAuthenticationv1.PasswordSessionVerificationRequest_Recovery{Recovery: code},
		}

		res, err := gatewayAuthenticationServiceClient.PasswordSessionVerification(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, res)
		assert.True(t, res.GetDisabledTwoFactor())
	})
}

func seedPasswordSessionVerification(
	t *testing.T,
	userID string,
	method enum.SecurityMethod,
) (context.Context, string, string) {
	t.Helper()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	email := cfg.Domain.GenerateEmail(userID)

	code, _, err := service.GenerateEmailCode(t.Context(), logger)
	require.NoError(t, err)

	session := rand.Text()

	data := &utils.PasswordVerificationSession{
		Key:     userID,
		ExAt:    time.Now().Add(utils.SessionExpiry),
		Code:    code,
		Email:   email,
		Session: session,
		Method:  string(method),
	}

	hSetErr := redis.HSet[utils.PasswordVerificationSession](
		t.Context(),
		utils.PasswordVerificationSessionPrefix,
		data,
		cfg.Client,
	)
	require.NoError(t, hSetErr)

	ctx := contextWithValue(t, userID)

	return ctx, session, code
}

func passwordSessionVerificationRateLimiter(
	t *testing.T,
	userID string,
	method enum.SecurityMethod,
	recovery bool,
) {
	t.Helper()

	for i := range 7 {
		ctx, _, code := seedPasswordSessionVerification(t, userID, method)

		session := rand.Text()

		req := &gatewayAuthenticationv1.PasswordSessionVerificationRequest{}

		switch method {
		case enum.SecurityMethodChangePassword:
			req = &gatewayAuthenticationv1.PasswordSessionVerificationRequest{
				Session: session,
				Code:    &gatewayAuthenticationv1.PasswordSessionVerificationRequest_Email{Email: code},
			}
		case enum.SecurityMethodEnableTwoFactor:
			req = &gatewayAuthenticationv1.PasswordSessionVerificationRequest{
				Session: session,
				Code:    &gatewayAuthenticationv1.PasswordSessionVerificationRequest_Email{Email: code},
			}
		case enum.SecurityMethodDisableTwoFactor:
			if recovery {
				req = &gatewayAuthenticationv1.PasswordSessionVerificationRequest{
					Session: session,
					Code: &gatewayAuthenticationv1.PasswordSessionVerificationRequest_Recovery{
						Recovery: "1234567890",
					},
				}
			} else {
				req = &gatewayAuthenticationv1.PasswordSessionVerificationRequest{
					Session: session,
					Code:    &gatewayAuthenticationv1.PasswordSessionVerificationRequest_Totp{Totp: "123456"},
				}
			}
		}

		res, err := gatewayAuthenticationServiceClient.PasswordSessionVerification(ctx, req)
		require.Error(t, err)
		assert.Nil(t, res)

		if i < 6 {
			assert.Equal(t, errs.ErrUnauthenticated, err)
		} else {
			assert.Equal(t, errs.ErrTooManyRequest, err)
		}
	}
}

func invalidCode(t *testing.T, method enum.SecurityMethod) {
	t.Helper()

	ctx, session, _ := seedPasswordSessionVerification(t, uuid.NewV7().String(), method)
	req := &gatewayAuthenticationv1.PasswordSessionVerificationRequest{
		Session: session,
		Code:    &gatewayAuthenticationv1.PasswordSessionVerificationRequest_Email{Email: "12345678"},
	}

	res, err := gatewayAuthenticationServiceClient.PasswordSessionVerification(ctx, req)
	require.Error(t, err)
	assert.Nil(t, res)
	assert.Equal(t, errs.ErrInvalidCode, err)
}

func seedPasswordSessionVerificationDisable(t *testing.T, recovery bool) (
	context.Context,
	string,
	string,
	[]string,
) {
	t.Helper()
	userID, secret, recoveryCodes := seedTwoFactor(t, recovery)

	ctx, session, _ := seedPasswordSessionVerification(t, userID, enum.SecurityMethodDisableTwoFactor)
	return ctx, session, secret, recoveryCodes
}

func seedSuccessEnable(t *testing.T) (context.Context, string, string) {
	t.Helper()

	userID, seedErr := seedUser(
		t.Context(),
		cfg.Domain.GenerateEmail(uuid.NewV7().String()),
		"Password@1234",
		enum.UserStatusActive,
		true,
	)
	require.NoError(t, seedErr)

	ctx, session, code := seedPasswordSessionVerification(t, userID, enum.SecurityMethodEnableTwoFactor)

	return ctx, session, code
}
