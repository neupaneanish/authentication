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

	"neupaneanish.com.np/authentication/internal/enum"

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

		ctx := contextWithValue(t, uuid.NewV7(), enum.UserRoleUser)

		req := &gatewayAuthenticationv1.LogoutRequest{}

		res, err := gatewayAuthenticationServiceClient.Logout(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, res)
	})

	t.Run("Logout All Success", func(t *testing.T) {
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
	userID := uuid.NewV7()
	session := rand.Text()

	accessData := &utils.Session{
		Key:      session,
		ExAt:     time.Now().Add(utils.AccessSessionExpiry),
		UserID:   userID.String(),
		Role:     string(enum.UserRoleUser),
		Username: rand.Text(),
	}

	accessHSetErr := redis.HSet[utils.Session](
		t.Context(),
		utils.SessionPrefix,
		accessData,
		cfg.Client,
	)
	require.NoError(t, accessHSetErr)

	sAddAccessErr := redis.SAdd(
		t.Context(),
		utils.SessionPrefix+userID.String(),
		session,
		utils.AccessSessionExpiry,
		cfg.Client,
	)
	require.NoError(t, sAddAccessErr)

	md := metadata.Pairs(
		"x-user-id", userID.String(),
		"x-role", string(enum.UserRoleUser),
		"x-session", session,
		"x-username", rand.Text(),
	)

	ctx := metadata.NewOutgoingContext(t.Context(), md)
	return ctx
}
