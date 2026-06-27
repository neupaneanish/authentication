//go:build integration

package service_test

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valkey-io/valkey-go"
	"neupaneanish.com.np/authentication/internal/enum"
	"neupaneanish.com.np/authentication/internal/errs"
	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"
	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/internal/utils"
)

func TestAccountVerification(t *testing.T) {
	t.Parallel()

	t.Run("Session not found", func(t *testing.T) {
		t.Parallel()
		session := rand.Text()
		code := "12345678"
		req := &externalAuthenticationv1.AccountVerificationRequest{Session: session, Code: code}
		response, responseErr := externalAuthenticationServiceClient.AccountVerification(t.Context(), req)
		require.Error(t, responseErr)
		assert.Nil(t, response)
		assert.Equal(t, errs.ErrSessionExpired, responseErr)
	})

	t.Run("Rate Limiter", func(t *testing.T) {
		t.Parallel()
		session := rand.Text()
		code := "12345678"
		userID := uuid.NewString()

		seedAccountVerificationSession(
			t,
			session,
			userID,
			"test",
			"test",
			code,
			false,
			cfg.Domain.GenerateEmail(session),
			cfg.Client,
		)

		for i := range 6 {
			req := &externalAuthenticationv1.AccountVerificationRequest{Session: session, Code: code}
			response, responseErr := externalAuthenticationServiceClient.AccountVerification(t.Context(), req)
			require.Error(t, responseErr)
			assert.Nil(t, response)
			if i < 5 {
				assert.Equal(t, errs.ErrSessionExpired, responseErr)
			} else {
				assert.Equal(t, errs.ErrTooManyRequest, responseErr)
			}
		}
	})

	t.Run("Rate Limiter UserID", func(t *testing.T) {
		t.Parallel()
		session := rand.Text()
		newSession := rand.Text()
		code := "12345678"
		userID := uuid.NewString()
		seedAccountVerificationSession(
			t,
			session,
			userID,
			"test",
			"test",
			code,
			false,
			cfg.Domain.GenerateEmail(session),
			cfg.Client,
		)
		seedAccountVerificationSession(
			t,
			newSession,
			userID,
			"test",
			"test",
			code,
			false,
			cfg.Domain.GenerateEmail(newSession),
			cfg.Client,
		)

		for i := range 6 {
			if i < 5 {
				req := &externalAuthenticationv1.AccountVerificationRequest{Session: session, Code: "12345679"}
				response, responseErr := externalAuthenticationServiceClient.AccountVerification(t.Context(), req)
				require.Error(t, responseErr)
				assert.Nil(t, response)
				assert.Equal(t, errs.ErrInvalidCode, responseErr)
			} else {
				req := &externalAuthenticationv1.AccountVerificationRequest{Session: newSession, Code: "12345679"}
				response, responseErr := externalAuthenticationServiceClient.AccountVerification(t.Context(), req)
				require.Error(t, responseErr)
				assert.Nil(t, response)
				assert.Equal(t, errs.ErrTooManyRequest, responseErr)
			}
		}
	})

	t.Run("Register", func(t *testing.T) {
		t.Parallel()
		verificationMethod(t, enum.MethodRegister)
	})

	t.Run("Forget Password", func(t *testing.T) {
		t.Parallel()
		verificationMethod(t, enum.MethodForgetPassword)
	})

	t.Run("Login", func(t *testing.T) {
		t.Parallel()
		verificationMethod(t, enum.MethodLogin)
	})
}

func seedAccountVerificationSession(
	t *testing.T,
	session string,
	userID string,
	role enum.UserRole,
	method enum.Method,
	code string,
	twoFactor bool,
	email string,
	client valkey.Client,
) {
	t.Helper()

	data := &utils.AccountVerificationSession{
		Key:       session,
		ExAt:      time.Now().Add(utils.SessionExpiry),
		UserID:    userID,
		Role:      string(role),
		Method:    string(method),
		Code:      code,
		TwoFactor: twoFactor,
		Email:     email,
	}

	hSetErr := redis.HSet[utils.AccountVerificationSession](
		t.Context(),
		utils.AccountVerificationSessionPrefix,
		data,
		client,
	)
	require.NoError(t, hSetErr)
}

func verificationMethod(t *testing.T, method enum.Method) {
	t.Helper()

	t.Run("Two Factor Enabled", func(t *testing.T) {
		t.Parallel()
		session := rand.Text()
		code := "12345678"

		email := cfg.Domain.GenerateEmail(session)

		if method == enum.MethodLogin {
			userID, err := seedUser(t.Context(), email, "Password@12345", enum.UserStatusPending, false)
			require.NoError(t, err)
			seedAccountVerificationSession(
				t,
				session,
				userID,
				enum.UserRoleUser,
				method,
				code,
				true,
				email,
				cfg.Client,
			)
		} else {
			seedAccountVerificationSession(
				t,
				session,
				uuid.NewString(),
				enum.UserRoleUser,
				method,
				code,
				true,
				email,
				cfg.Client,
			)
		}

		req := &externalAuthenticationv1.AccountVerificationRequest{Session: session, Code: code}
		response, responseErr := externalAuthenticationServiceClient.AccountVerification(t.Context(), req)

		if method == enum.MethodLogin {
			require.NoError(t, responseErr)
			require.NotNil(t, response)
		} else {
			require.Error(t, responseErr)
			assert.Nil(t, response)
			assert.Equal(t, errs.ErrSessionExpired, responseErr)
		}
	})

	t.Run("Two Factor Disabled", func(t *testing.T) {
		t.Parallel()
		session := rand.Text()
		email := cfg.Domain.GenerateEmail(session)
		userID, err := seedUser(
			t.Context(),
			email,
			"Password@123456",
			enum.UserStatusPending,
			false,
		)
		require.NoError(t, err)
		code := "12345678"

		seedAccountVerificationSession(
			t,
			session,
			userID,
			enum.UserRoleUser,
			method,
			code,
			false,
			email,
			cfg.Client,
		)
		req := &externalAuthenticationv1.AccountVerificationRequest{Session: session, Code: code}
		response, responseErr := externalAuthenticationServiceClient.AccountVerification(t.Context(), req)
		require.NoError(t, responseErr)
		assert.NotNil(t, response)
	})

	t.Run("Invalid User", func(t *testing.T) {
		t.Parallel()
		session := rand.Text()
		code := "ABCD1234"
		seedAccountVerificationSession(
			t,
			session,
			uuid.NewString(),
			"test",
			method,
			code,
			false,
			cfg.Domain.GenerateEmail(session),
			cfg.Client,
		)

		req := &externalAuthenticationv1.AccountVerificationRequest{Session: session, Code: code}
		response, responseErr := externalAuthenticationServiceClient.AccountVerification(t.Context(), req)
		require.Error(t, responseErr)
		assert.Nil(t, response)
		assert.Equal(t, errs.ErrAccountAlreadyVerified, responseErr)
	})
}
