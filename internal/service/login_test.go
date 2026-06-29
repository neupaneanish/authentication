//go:build integration

package service_test

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"neupaneanish.com.np/authentication/internal/enum"
	"neupaneanish.com.np/authentication/internal/errs"
	passwordv1 "neupaneanish.com.np/authentication/internal/protobuf/common/password/v1"
	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"
	"neupaneanish.com.np/authentication/internal/repository"
)

func TestLogin(t *testing.T) {
	t.Parallel()

	t.Run("Not register", func(t *testing.T) {
		t.Parallel()
		email := cfg.Domain.GenerateEmail(rand.Text())
		req := &externalAuthenticationv1.LoginRequest{
			Email: email,
			Password: &passwordv1.Password{
				Value: "Password@1234",
			},
		}

		response, responseErr := externalAuthenticationServiceClient.Login(t.Context(), req)
		require.Error(t, responseErr)
		assert.Nil(t, response)

		assert.Equal(t, errs.ErrInvalidCredentials, responseErr)
	})

	t.Run("Invalid email", func(t *testing.T) {
		t.Parallel()

		email := fmt.Sprintf("%s@test.com", rand.Text())
		req := &externalAuthenticationv1.LoginRequest{
			Email: email,
			Password: &passwordv1.Password{
				Value: "Password@1234",
			},
		}

		response, responseErr := externalAuthenticationServiceClient.Login(t.Context(), req)
		require.Error(t, responseErr)
		assert.Nil(t, response)

		assert.Equal(t, errs.ErrInvalidCredentials, responseErr)
	})

	t.Run("Registered user", func(t *testing.T) {
		t.Parallel()
		email := cfg.Domain.GenerateEmail(rand.Text())
		password := "Test@123456"
		_, err := seedUser(t.Context(), email, password, enum.UserStatusActive, true)
		require.NoError(t, err)

		req := &externalAuthenticationv1.LoginRequest{
			Email:    email,
			Password: &passwordv1.Password{Value: password},
		}

		response, responseErr := externalAuthenticationServiceClient.Login(t.Context(), req)
		require.NoError(t, responseErr)
		assert.NotNil(t, response)
	})

	t.Run("Invalid Credentials", func(t *testing.T) {
		t.Parallel()
		email := cfg.Domain.GenerateEmail(rand.Text())
		password := "Test@123456"
		_, err := seedUser(t.Context(), email, password, enum.UserStatusActive, true)
		require.NoError(t, err)

		req := &externalAuthenticationv1.LoginRequest{
			Email: email,
			Password: &passwordv1.Password{
				Value: "Password@123",
			},
		}

		response, responseErr := externalAuthenticationServiceClient.Login(t.Context(), req)
		require.Error(t, responseErr)
		assert.Nil(t, response)

		assert.Equal(t, errs.ErrInvalidCredentials, responseErr)
	})

	t.Run("Pending", func(t *testing.T) {
		t.Parallel()
		email := cfg.Domain.GenerateEmail(rand.Text())
		password := "Test@123456"
		userIDStr, err := seedUser(t.Context(), email, password, enum.UserStatusPending, false)
		require.NoError(t, err)

		userID := uuid.MustParse(userIDStr)
		verifyEmailParams := &repository.VerifyEmailParams{
			Status:    enum.UserStatusPending,
			UpdatedBy: userID,
			ID:        userID,
		}

		user, verifyEmailErr := cfg.Repository.VerifyEmail(t.Context(), verifyEmailParams)
		require.NoError(t, verifyEmailErr)
		assert.NotNil(t, user)

		req := &externalAuthenticationv1.LoginRequest{
			Email: email,
			Password: &passwordv1.Password{
				Value: password,
			},
		}

		response, responseErr := externalAuthenticationServiceClient.Login(t.Context(), req)
		require.Error(t, responseErr)
		assert.Nil(t, response)

		assert.Equal(t, errs.ErrAccountPending, responseErr)
	})

	t.Run("Restricted", func(t *testing.T) {
		t.Parallel()
		email := cfg.Domain.GenerateEmail(rand.Text())
		password := "Test@123456"
		_, err := seedUser(t.Context(), email, password, enum.UserStatusLocked, false)
		require.NoError(t, err)

		req := &externalAuthenticationv1.LoginRequest{
			Email: email,
			Password: &passwordv1.Password{
				Value: password,
			},
		}

		response, responseErr := externalAuthenticationServiceClient.Login(t.Context(), req)
		require.Error(t, responseErr)
		assert.Nil(t, response)

		assert.Equal(t, errs.ErrAccountRestricted, responseErr)
	})

	t.Run("Soft Delete", func(t *testing.T) {
		t.Parallel()
		email := cfg.Domain.GenerateEmail(rand.Text())
		password := "Test@123456"
		_, err := seedUser(t.Context(), email, password, enum.UserStatusDeleted, false)
		require.NoError(t, err)

		req := &externalAuthenticationv1.LoginRequest{
			Email: email,
			Password: &passwordv1.Password{
				Value: password,
			},
		}

		response, responseErr := externalAuthenticationServiceClient.Login(t.Context(), req)
		require.Error(t, responseErr)
		assert.Nil(t, response)

		assert.Equal(t, errs.ErrInvalidCredentials, responseErr)
	})

	t.Run("Two factor", func(t *testing.T) {
		t.Parallel()
		email := cfg.Domain.GenerateEmail(rand.Text())
		password := "Test@123456"
		uID, err := seedUser(t.Context(), email, password, enum.UserStatusActive, true)
		require.NoError(t, err)

		secret, secretErr := cfg.TwoFactor.Generate("Test")
		require.NoError(t, secretErr)

		encrypt, encryptErr := cfg.TwoFactor.Encrypt(secret.Secret)
		require.NoError(t, encryptErr)

		userID := uuid.MustParse(uID)
		params := &repository.CreateTwoFactorParams{
			UserID:    userID,
			Secret:    encrypt,
			CreatedBy: userID,
			UpdatedBy: userID,
		}

		row, rowErr := cfg.Repository.CreateTwoFactor(t.Context(), params)
		require.NoError(t, rowErr)
		assert.Equal(t, int64(1), row.RowsAffected())

		req := &externalAuthenticationv1.LoginRequest{
			Email: email,
			Password: &passwordv1.Password{
				Value: password,
			},
		}

		response, responseErr := externalAuthenticationServiceClient.Login(t.Context(), req)
		require.NoError(t, responseErr)
		assert.NotNil(t, response)
	})

	t.Run("Verification", func(t *testing.T) {
		t.Parallel()

		email := cfg.Domain.GenerateEmail(rand.Text())
		password := "Test@123456"

		_, err := seedUser(t.Context(), email, password, enum.UserStatusPending, false)
		require.NoError(t, err)

		req := &externalAuthenticationv1.LoginRequest{
			Email: email,
			Password: &passwordv1.Password{
				Value: password,
			},
		}

		response, responseErr := externalAuthenticationServiceClient.Login(t.Context(), req)
		require.NoError(t, responseErr)
		assert.NotNil(t, response)
	})

	t.Run("Verification invalid password", func(t *testing.T) {
		t.Parallel()

		email := cfg.Domain.GenerateEmail(rand.Text())
		password := "Test@123456"

		_, err := seedUser(t.Context(), email, password, enum.UserStatusPending, false)
		require.NoError(t, err)

		req := &externalAuthenticationv1.LoginRequest{
			Email: email,
			Password: &passwordv1.Password{
				Value: "Test@1234567",
			},
		}

		response, responseErr := externalAuthenticationServiceClient.Login(t.Context(), req)
		require.Error(t, responseErr)
		assert.Nil(t, response)

		assert.Equal(t, errs.ErrInvalidCredentials, responseErr)
	})

	t.Run("Verification email not verified", func(t *testing.T) {
		t.Parallel()

		email := cfg.Domain.GenerateEmail(rand.Text())
		password := "Test@123456"

		_, err := seedUser(t.Context(), email, password, enum.UserStatusActive, false)
		require.NoError(t, err)

		req := &externalAuthenticationv1.LoginRequest{
			Email: email,
			Password: &passwordv1.Password{
				Value: "Test@123456",
			},
		}

		response, responseErr := externalAuthenticationServiceClient.Login(t.Context(), req)
		require.NoError(t, responseErr)
		assert.NotNil(t, response)
	})

	t.Run("Rate Limiter", func(t *testing.T) {
		t.Parallel()

		email := cfg.Domain.GenerateEmail(rand.Text())

		req := &externalAuthenticationv1.LoginRequest{
			Email: email,
			Password: &passwordv1.Password{
				Value: "Password@1234",
			},
		}

		for i := range 6 {
			response, responseErr := externalAuthenticationServiceClient.Login(t.Context(), req)
			if i < 5 {
				require.Error(t, responseErr)
				assert.Nil(t, response)
				assert.Equal(t, errs.ErrInvalidCredentials, responseErr)
			} else {
				require.Error(t, responseErr)
				assert.Nil(t, response)

				assert.Equal(t, errs.ErrTooManyRequest, responseErr)
			}
		}
	})

	t.Run("Permission Denied", func(t *testing.T) {
		t.Parallel()
		md := metadata.Pairs(
			"x-user-id", uuid.NewString(),
			"x-role", "test",
			"x-jti", uuid.NewString(),
		)

		ctx := metadata.NewOutgoingContext(t.Context(), md)

		email := cfg.Domain.GenerateEmail(rand.Text())
		req := &externalAuthenticationv1.LoginRequest{
			Email: email,
			Password: &passwordv1.Password{
				Value: "Password@1234",
			},
		}

		response, responseErr := externalAuthenticationServiceClient.Login(ctx, req)
		require.Error(t, responseErr)
		assert.Nil(t, response)

		assert.Equal(t, errs.ErrPermissionDenied, responseErr)
	})
}
