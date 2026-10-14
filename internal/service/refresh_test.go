//go:build integration

package service_test

import (
	"context"
	"crypto/rand"
	"testing"
	"time"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"

	"neupaneanish.com.np/authentication/internal/enum"
	"neupaneanish.com.np/authentication/internal/errs"
	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/internal/utils"
)

func TestRefresh(t *testing.T) {
	t.Parallel()

	t.Run("Limiter UserID", func(t *testing.T) {
		t.Parallel()

		req := &gatewayAuthenticationv1.RefreshRequest{}

		ctx := contextWithValue(t, uuid.NewV7(), enum.UserRoleUser)

		for i := range 3 {
			response, responseErr := gatewayAuthenticationServiceClient.Refresh(ctx, req)
			require.Error(t, responseErr)
			assert.Nil(t, response)
			if i < 2 {
				assert.Equal(t, errs.ErrInvalidTokenOrExpired, responseErr)
			} else {
				assert.Equal(t, errs.ErrTooManyRequest, responseErr)
			}
		}
	})

	t.Run("Before 10 minutes", func(t *testing.T) {
		t.Parallel()

		ctx := setupSessionRedis(t, 11*time.Minute)

		req := &gatewayAuthenticationv1.RefreshRequest{}

		res, err := gatewayAuthenticationServiceClient.Refresh(ctx, req)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrUnauthenticated, err)
	})

	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		ctx := setupSessionRedis(t, 10*time.Minute)

		req := &gatewayAuthenticationv1.RefreshRequest{}

		res, err := gatewayAuthenticationServiceClient.Refresh(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, res)
		assert.NotNil(t, res.GetExpires())
	})
}

func setupSessionRedis(
	t *testing.T,
	ttl time.Duration,
) context.Context {
	t.Helper()

	token := utils.GenerateToken(utils.SessionExpiry)
	userID := uuid.NewV7()
	accessSession := &utils.Session{
		Key:      token.Session,
		ExAt:     time.Now().Add(ttl),
		UserID:   userID.String(),
		Role:     string(enum.UserRoleUser),
		Username: rand.Text(),
	}

	hSetErr := redis.HSet[utils.Session](t.Context(), utils.SessionPrefix, accessSession, cfg.Client)
	require.NoError(t, hSetErr)

	sErr := redis.SAdd(
		t.Context(),
		utils.SessionPrefix+userID.String(),
		token.Session,
		ttl,
		cfg.Client,
	)
	require.NoError(t, sErr)
	md := metadata.Pairs(
		"x-user-id", userID.String(),
		"x-role", string(enum.UserRoleUser),
		"x-session", token.Session,
		"x-username", rand.Text(),
	)

	ctx := metadata.NewOutgoingContext(t.Context(), md)
	return ctx
}
