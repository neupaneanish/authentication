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

	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/internal/utils"
)

func TestLogout(t *testing.T) {
	t.Parallel()

	t.Run("Logout Success", func(t *testing.T) {
		t.Parallel()
		ctx := seedLogout(t)

		req := &gatewayAuthenticationv1.LogoutRequest{}

		res, err := gatewayAuthenticationServiceClient.Logout(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, res)
	})

	t.Run("Logout Success Record Not Found", func(t *testing.T) {
		t.Parallel()

		md := metadata.Pairs(
			"x-user-id", uuid.NewV7().String(),
			"x-role", "test",
			"x-jti", uuid.NewV7().String(),
		)

		ctx := metadata.NewOutgoingContext(t.Context(), md)

		req := &gatewayAuthenticationv1.LogoutRequest{}

		res, err := gatewayAuthenticationServiceClient.Logout(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, res)
	})
}

func TestLogoutAll(t *testing.T) {
	t.Parallel()

	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		ctx := seedLogout(t)

		req := &gatewayAuthenticationv1.LogoutAllRequest{}
		res, err := gatewayAuthenticationServiceClient.LogoutAll(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, res)
	})
}

func seedLogout(t *testing.T) context.Context {
	t.Helper()
	userID := uuid.NewV7().String()
	jti := uuid.NewV7().String()
	refresh := rand.Text()

	accessData := &utils.LoginAccessSession{
		Key:     jti,
		ExAt:    time.Now().Add(utils.AccessSessionExpiry),
		UserID:  userID,
		Role:    "test",
		Refresh: refresh,
	}

	accessHSetErr := redis.HSet[utils.LoginAccessSession](
		t.Context(),
		utils.LoginAccessSessionPrefix,
		accessData,
		cfg.Client,
	)
	require.NoError(t, accessHSetErr)

	refreshData := &utils.LoginRefreshSession{
		Key:    refresh,
		ExAt:   time.Now().Add(utils.RefreshSessionExpiry),
		UserID: userID,
		Role:   "test",
		ID:     jti,
	}

	refreshHSetErr := redis.HSet[utils.LoginRefreshSession](
		t.Context(),
		utils.LoginRefreshSessionPrefix,
		refreshData,
		cfg.Client,
	)
	require.NoError(t, refreshHSetErr)

	sAddAccessErr := redis.SAdd(t.Context(), utils.UserSessionPrefix+userID, jti, utils.AccessSessionExpiry, cfg.Client)
	require.NoError(t, sAddAccessErr)

	isAddRefreshErr := redis.SAdd(
		t.Context(),
		utils.UserSessionPrefix+userID,
		refresh,
		utils.RefreshSessionExpiry,
		cfg.Client,
	)
	require.NoError(t, isAddRefreshErr)

	md := metadata.Pairs(
		"x-user-id", userID,
		"x-role", "test",
		"x-jti", jti,
	)
	ctx := metadata.NewOutgoingContext(t.Context(), md)
	return ctx
}
