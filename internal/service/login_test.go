//go:build integration

package service_test

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"neupaneanish.com.np/api/internal/enum"
	authv1 "neupaneanish.com.np/api/internal/protobuf/auth/v1"
	passwordv1 "neupaneanish.com.np/api/internal/protobuf/common/password/v1"
	"neupaneanish.com.np/api/internal/repository"
)

func TestLogin(t *testing.T) {
	t.Parallel()
	t.Run("Not register", func(t *testing.T) {
		t.Parallel()
		email := fmt.Sprintf("%s@test.com", rand.Text())
		req := &authv1.LoginRequest{
			Email: email,
			Password: &passwordv1.Password{
				Value: "Password@1234",
			},
		}

		response, responseErr := authServiceClient.Login(t.Context(), req)
		require.Error(t, responseErr)
		assert.Nil(t, response)

		st, _ := status.FromError(responseErr)
		assert.Equal(t, codes.Unauthenticated, st.Code())
	})

	t.Run("Registered user", func(t *testing.T) {
		t.Parallel()
		email := fmt.Sprintf("%s@test.com", rand.Text())
		password := "Test@123456"
		_, err := seedUser(t.Context(), email, password, enum.UserStatusActive)
		require.NoError(t, err)

		req := &authv1.LoginRequest{
			Email:    email,
			Password: &passwordv1.Password{Value: password},
		}

		response, responseErr := authServiceClient.Login(t.Context(), req)
		require.NoError(t, responseErr)
		assert.NotNil(t, response)
	})

	t.Run("Invalid Credentials", func(t *testing.T) {
		t.Parallel()
		email := fmt.Sprintf("%s@test.com", rand.Text())
		password := "Test@123456"
		_, err := seedUser(t.Context(), email, password, enum.UserStatusActive)
		require.NoError(t, err)

		req := &authv1.LoginRequest{
			Email: email,
			Password: &passwordv1.Password{
				Value: "Password@123",
			},
		}

		response, responseErr := authServiceClient.Login(t.Context(), req)
		require.Error(t, responseErr)
		assert.Nil(t, response)

		st, _ := status.FromError(responseErr)
		assert.Equal(t, codes.Unauthenticated, st.Code())
	})

	t.Run("Pending", func(t *testing.T) {
		t.Parallel()
		email := fmt.Sprintf("%s@test.com", rand.Text())
		password := "Test@123456"
		_, err := seedUser(t.Context(), email, password, enum.UserStatusPending)
		require.NoError(t, err)

		req := &authv1.LoginRequest{
			Email: email,
			Password: &passwordv1.Password{
				Value: password,
			},
		}

		response, responseErr := authServiceClient.Login(t.Context(), req)
		require.Error(t, responseErr)
		assert.Nil(t, response)

		st, _ := status.FromError(responseErr)
		assert.Equal(t, codes.PermissionDenied, st.Code())
	})

	t.Run("Restricted", func(t *testing.T) {
		t.Parallel()
		email := fmt.Sprintf("%s@test.com", rand.Text())
		password := "Test@123456"
		_, err := seedUser(t.Context(), email, password, enum.UserStatusLocked)
		require.NoError(t, err)

		req := &authv1.LoginRequest{
			Email: email,
			Password: &passwordv1.Password{
				Value: password,
			},
		}

		response, responseErr := authServiceClient.Login(t.Context(), req)
		require.Error(t, responseErr)
		assert.Nil(t, response)

		st, _ := status.FromError(responseErr)
		assert.Equal(t, codes.PermissionDenied, st.Code())
	})

	t.Run("Soft Delete", func(t *testing.T) {
		t.Parallel()
		email := fmt.Sprintf("%s@test.com", rand.Text())
		password := "Test@123456"
		_, err := seedUser(t.Context(), email, password, enum.UserStatusDeleted)
		require.NoError(t, err)

		req := &authv1.LoginRequest{
			Email: email,
			Password: &passwordv1.Password{
				Value: password,
			},
		}

		response, responseErr := authServiceClient.Login(t.Context(), req)
		require.Error(t, responseErr)
		assert.Nil(t, response)

		st, _ := status.FromError(responseErr)
		assert.Equal(t, codes.Unauthenticated, st.Code())
	})

	t.Run("Two factor", func(t *testing.T) {
		t.Parallel()
		email := fmt.Sprintf("%s@test.com", rand.Text())
		password := "Test@123456"
		uID, err := seedUser(t.Context(), email, password, enum.UserStatusActive)
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

		req := &authv1.LoginRequest{
			Email: email,
			Password: &passwordv1.Password{
				Value: password,
			},
		}

		response, responseErr := authServiceClient.Login(t.Context(), req)
		require.NoError(t, responseErr)
		assert.NotNil(t, response)
	})

	t.Run("Rate Limiter", func(t *testing.T) {
		email := fmt.Sprintf("%s@test.com", rand.Text())
		t.Run("Allowed", func(t *testing.T) {
			for range 5 {
				req := &authv1.LoginRequest{
					Email: email,
					Password: &passwordv1.Password{
						Value: "Password@1234",
					},
				}

				response, err := authServiceClient.Login(t.Context(), req)
				require.Error(t, err)
				assert.Nil(t, response)

				st, _ := status.FromError(err)
				assert.Equal(t, codes.Unauthenticated, st.Code())
			}
		})

		t.Run("Blocked", func(t *testing.T) {
			req := &authv1.LoginRequest{
				Email: email,
				Password: &passwordv1.Password{
					Value: "Password@1234",
				},
			}

			response, err := authServiceClient.Login(t.Context(), req)
			require.Error(t, err)
			assert.Nil(t, response)

			st, _ := status.FromError(err)
			assert.Equal(t, codes.ResourceExhausted, st.Code())
		})
	})
}
