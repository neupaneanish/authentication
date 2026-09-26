//go:build integration

package service_test

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"neupaneanish.com.np/authentication/internal/errs"

	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"

	"neupaneanish.com.np/authentication/internal/redis"

	"neupaneanish.com.np/authentication/internal/utils"

	"neupaneanish.com.np/authentication/internal/enum"
)

func TestChangeEmail(t *testing.T) {
	t.Parallel()

	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		email := fmt.Sprintf("%s@neupaneanish.com.np", rand.Text()[:8])
		id, session, _ := seedChangeEmail(t)

		ctx := contextWithValue(t, id, enum.UserRoleUser)

		req := &gatewayAuthenticationv1.ChangeEmailRequest{
			Session: session,
			Email:   email,
		}

		res, err := gatewayAuthenticationServiceClient.ChangeEmail(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, res)
	})

	t.Run("UniqueViolation", func(t *testing.T) {
		t.Parallel()

		id, session, _ := seedChangeEmail(t)
		_, _, email := seedChangeEmail(t)

		ctx := contextWithValue(t, id, enum.UserRoleUser)

		req := &gatewayAuthenticationv1.ChangeEmailRequest{
			Session: session,
			Email:   email,
		}

		res, err := gatewayAuthenticationServiceClient.ChangeEmail(ctx, req)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrEmailAlreadyExists, err)
	})

	t.Run("Invalid Session", func(t *testing.T) {
		t.Parallel()

		id, _, _ := seedChangeEmail(t)

		ctx := contextWithValue(t, id, enum.UserRoleUser)

		req := &gatewayAuthenticationv1.ChangeEmailRequest{
			Session: rand.Text(),
			Email:   "anish@neupaneanish.com.np",
		}

		res, err := gatewayAuthenticationServiceClient.ChangeEmail(ctx, req)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrSessionExpired, err)
	})

	t.Run("Invalid Email", func(t *testing.T) {
		t.Parallel()

		id, session, _ := seedChangeEmail(t)

		ctx := contextWithValue(t, id, enum.UserRoleUser)

		req := &gatewayAuthenticationv1.ChangeEmailRequest{
			Session: session,
			Email:   "testtest@gmail.com",
		}

		res, err := gatewayAuthenticationServiceClient.ChangeEmail(ctx, req)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrInvalidEmail, err)
	})

	t.Run("Rate Limiter", func(t *testing.T) {
		t.Parallel()

		ctx := contextWithValue(t, uuid.NewV7(), enum.UserRoleUser)

		req := &gatewayAuthenticationv1.ChangeEmailRequest{
			Session: rand.Text(),
			Email:   "testtest@gmail.com",
		}

		for i := range 7 {
			res, err := gatewayAuthenticationServiceClient.ChangeEmail(ctx, req)
			require.Error(t, err)
			assert.Nil(t, res)
			if i < 6 {
				assert.Equal(t, errs.ErrSessionExpired, err)
			} else {
				assert.Equal(t, errs.ErrTooManyRequest, err)
			}
		}
	})
}

func seedChangeEmail(t *testing.T) (uuid.UUID, string, string) {
	t.Helper()
	email := fmt.Sprintf("%s@neupaneanish.com.np", rand.Text()[:8])
	id, err := seedUser(t.Context(), email, "Password@12345", enum.UserStatusActive, false, enum.UserRoleUser)
	require.NoError(t, err)
	session := rand.Text()

	data := &utils.ChangeEmailSession{
		Key:     id.String(),
		ExAt:    time.Now().Add(utils.SessionExpiry),
		Session: session,
	}
	hErr := redis.HSet[utils.ChangeEmailSession](t.Context(), utils.ChangeEmailSessionPrefix, data, cfg.Client)
	require.NoError(t, hErr)

	return id, session, email
}
