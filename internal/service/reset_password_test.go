//go:build integration

package service_test

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"neupaneanish.com.np/api/internal/enum"
	authv1 "neupaneanish.com.np/api/internal/protobuf/auth/v1"
	passwordv1 "neupaneanish.com.np/api/internal/protobuf/common/password/v1"
	"neupaneanish.com.np/api/internal/redis"
	"neupaneanish.com.np/api/internal/service"
)

func TestResetPassword(t *testing.T) {
	t.Parallel()
	oldPassword := "Reset@Password1"
	newPassword := "Reset@Password12"

	t.Run("Invalid session", func(t *testing.T) {
		t.Parallel()
		req := &authv1.ResetPasswordRequest{
			Session:         rand.Text(),
			Password:        &passwordv1.Password{Value: newPassword},
			ConfirmPassword: &passwordv1.Password{Value: newPassword},
		}

		response, responseErr := authServiceClient.ResetPassword(t.Context(), req)
		require.Error(t, responseErr)
		assert.Nil(t, response)

		st, _ := status.FromError(responseErr)
		assert.Equal(t, codes.Aborted, st.Code())
	})

	t.Run("Valid session previous password", func(t *testing.T) {
		t.Parallel()
		email := fmt.Sprintf("%s@test.com", rand.Text())
		session := seedUserResetPassword(t, email, oldPassword)
		req := &authv1.ResetPasswordRequest{
			Session:         session,
			Password:        &passwordv1.Password{Value: oldPassword},
			ConfirmPassword: &passwordv1.Password{Value: oldPassword},
		}

		response, responseErr := authServiceClient.ResetPassword(t.Context(), req)
		require.Error(t, responseErr)
		assert.Nil(t, response)

		st, _ := status.FromError(responseErr)
		assert.Equal(t, codes.AlreadyExists, st.Code())
	})

	t.Run("Valid session and password", func(t *testing.T) {
		t.Parallel()
		email := fmt.Sprintf("%s@test.com", rand.Text())
		session := seedUserResetPassword(t, email, oldPassword)
		req := &authv1.ResetPasswordRequest{
			Session:         session,
			Password:        &passwordv1.Password{Value: newPassword},
			ConfirmPassword: &passwordv1.Password{Value: newPassword},
		}

		response, responseErr := authServiceClient.ResetPassword(t.Context(), req)
		require.NoError(t, responseErr)
		assert.NotNil(t, response)
	})

	t.Run("No Passwords", func(t *testing.T) {
		t.Parallel()
		session := rand.Text()
		userID := uuid.NewString()

		data := &service.ResetPasswordSession{
			Key:    session,
			ExAt:   time.Now().Add(service.SessionExpiry),
			UserID: userID,
		}

		hSetErr := redis.HSet[service.ResetPasswordSession](
			t.Context(),
			service.ResetPasswordSessionPrefix,
			data,
			cfg.Client,
		)
		require.NoError(t, hSetErr)

		req := &authv1.ResetPasswordRequest{
			Session:         session,
			Password:        &passwordv1.Password{Value: oldPassword},
			ConfirmPassword: &passwordv1.Password{Value: oldPassword},
		}

		response, responseErr := authServiceClient.ResetPassword(t.Context(), req)
		require.Error(t, responseErr)
		assert.Nil(t, response)
		st, _ := status.FromError(responseErr)
		assert.Equal(t, codes.Aborted, st.Code())
	})

	t.Run("Rate limiter", func(t *testing.T) {
		email := fmt.Sprintf("%s@test.com", rand.Text())
		session := seedUserResetPassword(t, email, oldPassword)
		req := &authv1.ResetPasswordRequest{
			Session:         session,
			Password:        &passwordv1.Password{Value: oldPassword},
			ConfirmPassword: &passwordv1.Password{Value: oldPassword},
		}

		t.Run("Allowed", func(t *testing.T) {
			for range 5 {
				response, responseErr := authServiceClient.ResetPassword(t.Context(), req)
				require.Error(t, responseErr)
				assert.Nil(t, response)

				st, _ := status.FromError(responseErr)
				assert.Equal(t, codes.AlreadyExists, st.Code())
			}
		})

		t.Run("Blocked", func(t *testing.T) {
			response, responseErr := authServiceClient.ResetPassword(t.Context(), req)
			require.Error(t, responseErr)
			assert.Nil(t, response)

			st, _ := status.FromError(responseErr)
			assert.Equal(t, codes.ResourceExhausted, st.Code())
		})
	})
}

func seedUserResetPassword(t *testing.T, email string, password string) string {
	t.Helper()
	session := rand.Text()
	userID, seedErr := seedUser(t.Context(), email, password, enum.UserStatusActive)
	require.NoError(t, seedErr)

	data := &service.ResetPasswordSession{
		Key:    session,
		ExAt:   time.Now().Add(service.SessionExpiry),
		UserID: userID,
	}

	hSetErr := redis.HSet[service.ResetPasswordSession](
		t.Context(),
		service.ResetPasswordSessionPrefix,
		data,
		cfg.Client,
	)
	require.NoError(t, hSetErr)
	return session
}
