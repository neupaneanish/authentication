//go:build integration

package service_test

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"neupaneanish.com.np/authentication/internal/enum"
	"neupaneanish.com.np/authentication/internal/errs"
	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"
	"neupaneanish.com.np/authentication/internal/repository"
)

func TestForgetPassword(t *testing.T) {
	t.Parallel()

	t.Run("Invalid email", func(t *testing.T) {
		t.Parallel()
		email := fmt.Sprintf("%s@test.com", rand.Text())
		req := &externalAuthenticationv1.ForgetPasswordRequest{Email: email}

		response, err := externalAuthenticationServiceClient.ForgetPassword(t.Context(), req)
		require.NoError(t, err)
		assert.NotNil(t, response)
	})

	t.Run("Unregister email", func(t *testing.T) {
		t.Parallel()
		email := cfg.Domain.GenerateEmail(rand.Text())
		req := &externalAuthenticationv1.ForgetPasswordRequest{Email: email}

		response, err := externalAuthenticationServiceClient.ForgetPassword(t.Context(), req)
		require.NoError(t, err)
		assert.NotNil(t, response)
	})

	t.Run("Register email", func(t *testing.T) {
		t.Parallel()
		email := cfg.Domain.GenerateEmail(rand.Text())
		_, seedErr := seedUser(t.Context(), email, "forgetPassword@123456", enum.UserStatusActive, true)
		require.NoError(t, seedErr)

		req := &externalAuthenticationv1.ForgetPasswordRequest{Email: email}

		response, err := externalAuthenticationServiceClient.ForgetPassword(t.Context(), req)
		require.NoError(t, err)
		assert.NotNil(t, response)
	})

	t.Run("Email not verified", func(t *testing.T) {
		t.Parallel()

		email := cfg.Domain.GenerateEmail(rand.Text())
		_, seedErr := seedUser(t.Context(), email, "forgetPassword@123456", enum.UserStatusActive, false)
		require.NoError(t, seedErr)

		req := &externalAuthenticationv1.ForgetPasswordRequest{Email: email}

		response, responseErr := externalAuthenticationServiceClient.ForgetPassword(t.Context(), req)
		require.NoError(t, responseErr)
		assert.NotNil(t, response)
	})

	t.Run("Pending", func(t *testing.T) {
		t.Parallel()

		email := cfg.Domain.GenerateEmail(rand.Text())
		userIDStr, seedErr := seedUser(t.Context(), email, "forgetPassword@123456", enum.UserStatusPending, false)
		require.NoError(t, seedErr)

		userID := uuid.MustParse(userIDStr)
		verifyEmailParams := &repository.VerifyEmailParams{
			Status:    enum.UserStatusPending,
			UpdatedBy: userID,
			ID:        userID,
		}

		user, verifyEmailErr := cfg.Repository.VerifyEmail(t.Context(), verifyEmailParams)
		require.NoError(t, verifyEmailErr)
		assert.NotNil(t, user)

		req := &externalAuthenticationv1.ForgetPasswordRequest{Email: email}

		response, responseErr := externalAuthenticationServiceClient.ForgetPassword(t.Context(), req)
		require.Error(t, responseErr)
		assert.Nil(t, response)

		assert.Equal(t, errs.ErrAccountPending, responseErr)
	})

	t.Run("Verification", func(t *testing.T) {
		t.Parallel()

		email := cfg.Domain.GenerateEmail(rand.Text())
		_, seedErr := seedUser(t.Context(), email, "forgetPassword@123456", enum.UserStatusPending, false)
		require.NoError(t, seedErr)

		req := &externalAuthenticationv1.ForgetPasswordRequest{Email: email}

		response, responseErr := externalAuthenticationServiceClient.ForgetPassword(t.Context(), req)
		require.NoError(t, responseErr)
		assert.NotNil(t, response)
	})

	t.Run("Locked", func(t *testing.T) {
		t.Parallel()

		email := cfg.Domain.GenerateEmail(rand.Text())
		_, seedErr := seedUser(t.Context(), email, "forgetPassword@123456", enum.UserStatusLocked, false)
		require.NoError(t, seedErr)

		req := &externalAuthenticationv1.ForgetPasswordRequest{Email: email}

		response, err := externalAuthenticationServiceClient.ForgetPassword(t.Context(), req)
		require.NoError(t, err)
		assert.NotNil(t, response)
	})

	t.Run("Rate limiter", func(t *testing.T) {
		t.Parallel()

		email := cfg.Domain.GenerateEmail(rand.Text())
		req := &externalAuthenticationv1.ForgetPasswordRequest{Email: email}

		for i := range 5 {
			response, err := externalAuthenticationServiceClient.ForgetPassword(t.Context(), req)

			if i < 5 {
				require.NoError(t, err)
				assert.NotNil(t, response)
			} else {
				require.Error(t, err)
				assert.Nil(t, response)
				assert.Equal(t, errs.ErrTooManyRequest, err)
			}
		}
	})
}
