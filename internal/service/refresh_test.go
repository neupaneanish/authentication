//go:build integration

package service_test

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"neupaneanish.com.np/authentication/internal/errs"
	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"
	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/internal/utils"
)

func TestRefresh(t *testing.T) {
	t.Parallel()

	t.Run("Limiter Session", func(t *testing.T) {
		t.Parallel()

		req := &externalAuthenticationv1.RefreshRequest{Refresh: rand.Text()}

		for i := range 3 {
			response, responseErr := externalAuthenticationServiceClient.Refresh(t.Context(), req)
			require.Error(t, responseErr)
			assert.Nil(t, response)
			if i < 2 {
				assert.Equal(t, errs.ErrSessionExpired, responseErr)
			} else {
				assert.Equal(t, errs.ErrTooManyRequest, responseErr)
			}
		}
	})

	t.Run("Limiter UserID", func(t *testing.T) {
		t.Parallel()
		userID := uuid.NewString()

		md := metadata.Pairs(
			"x-user-id", userID,
			"x-role", "test",
			"x-jti", uuid.NewString(),
		)

		ctx := metadata.NewOutgoingContext(t.Context(), md)

		for i := range 5 {
			refresh := setupAccessRefreshRedis(t, userID)

			req := &externalAuthenticationv1.RefreshRequest{Refresh: refresh}
			response, responseErr := externalAuthenticationServiceClient.Refresh(ctx, req)
			if i < 4 {
				require.NoError(t, responseErr)
				assert.NotNil(t, response)
				assert.NotEmpty(t, response.Token.GetRefresh())
			} else {
				require.Error(t, responseErr)
				assert.Nil(t, response)
				assert.Equal(t, errs.ErrTooManyRequest, responseErr)
			}
		}
	})
}

func setupAccessRefreshRedis(t *testing.T, userID string) string {
	t.Helper()

	ctx := t.Context()
	refresh := rand.Text()
	access := rand.Text()

	accessSession := &utils.LoginAccessSession{
		Key:    access,
		ExAt:   time.Now().Add(utils.AccessSessionExpiry),
		UserID: userID,
	}

	hSetErr := redis.HSet[utils.LoginAccessSession](ctx, utils.LoginAccessSessionPrefix, accessSession, cfg.Client)
	require.NoError(t, hSetErr)

	refreshSession := &utils.LoginRefreshSession{
		Key:    refresh,
		ExAt:   time.Now().Add(utils.RefreshSessionExpiry),
		UserID: userID,
		Role:   "test",
		ID:     access,
	}

	rHSetErr := redis.HSet[utils.LoginRefreshSession](
		ctx,
		utils.LoginRefreshSessionPrefix,
		refreshSession,
		cfg.Client,
	)
	require.NoError(t, rHSetErr)
	return refresh
}
