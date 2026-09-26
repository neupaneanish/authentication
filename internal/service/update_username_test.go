//go:build integration

package service_test

import (
	"crypto/rand"
	"fmt"
	rand2 "math/rand"
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"neupaneanish.com.np/authentication/internal/errs"

	rootAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/root/authentication/v1"

	authenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/common/authentication/v1"
	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
	"neupaneanish.com.np/authentication/internal/repository"

	"neupaneanish.com.np/authentication/internal/enum"
)

func TestUpdateUsername(t *testing.T) {
	t.Parallel()

	t.Run("Gateway Success", func(t *testing.T) {
		t.Parallel()
		user := getUser(t)

		ctx := contextWithValue(t, user.ID, enum.UserRoleUser)

		req := &gatewayAuthenticationv1.UpdateUsernameRequest{
			Username: &authenticationv1.Username{
				Value:     fmt.Sprintf("username%d", rand2.Int63n(100000)),
				UpdatedAt: timestamppb.New(user.UpdatedAt),
			},
		}

		res, err := gatewayAuthenticationServiceClient.UpdateUsername(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, res)
	})

	t.Run("Gateway UniqueViolation", func(t *testing.T) {
		t.Parallel()
		user := getUser(t)
		user1 := getUser(t)

		ctx := contextWithValue(t, user.ID, enum.UserRoleUser)

		req := &gatewayAuthenticationv1.UpdateUsernameRequest{
			Username: &authenticationv1.Username{
				Value:     user1.Username,
				UpdatedAt: timestamppb.New(user.UpdatedAt),
			},
		}

		res, err := gatewayAuthenticationServiceClient.UpdateUsername(ctx, req)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrUsernameAlreadyExists, err)
	})

	t.Run("Gateway Conflict", func(t *testing.T) {
		t.Parallel()

		ctx := contextWithValue(t, uuid.NewV7(), enum.UserRoleUser)

		req := &gatewayAuthenticationv1.UpdateUsernameRequest{
			Username: &authenticationv1.Username{
				Value:     fmt.Sprintf("username%d", rand2.Int63n(100000)),
				UpdatedAt: timestamppb.Now(),
			},
		}

		res, err := gatewayAuthenticationServiceClient.UpdateUsername(ctx, req)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrConflict, err)
	})

	t.Run("Root Success", func(t *testing.T) {
		t.Parallel()
		user := getUser(t)

		ctx := contextWithValue(t, uuid.New(), enum.UserRoleRoot)

		req := &rootAuthenticationv1.UpdateUsernameRequest{
			Id: user.ID.String(),
			Username: &authenticationv1.Username{
				Value:     fmt.Sprintf("username%d", rand2.Int63n(100000)),
				UpdatedAt: timestamppb.New(user.UpdatedAt),
			},
		}

		res, err := rootAuthenticationServiceClient.UpdateUsername(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, res)
	})

	t.Run("Root UniqueViolation", func(t *testing.T) {
		t.Parallel()
		user := getUser(t)
		user2 := getUser(t)

		ctx := contextWithValue(t, uuid.New(), enum.UserRoleRoot)

		req := &rootAuthenticationv1.UpdateUsernameRequest{
			Id: user.ID.String(),
			Username: &authenticationv1.Username{
				Value:     user2.Username,
				UpdatedAt: timestamppb.New(user.UpdatedAt),
			},
		}

		res, err := rootAuthenticationServiceClient.UpdateUsername(ctx, req)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrUsernameAlreadyExists, err)
	})

	t.Run("Root Conflict", func(t *testing.T) {
		t.Parallel()

		ctx := contextWithValue(t, uuid.New(), enum.UserRoleRoot)

		req := &rootAuthenticationv1.UpdateUsernameRequest{
			Id: uuid.NewV7().String(),
			Username: &authenticationv1.Username{
				Value:     fmt.Sprintf("username%d", rand2.Int63n(100000)),
				UpdatedAt: timestamppb.Now(),
			},
		}

		res, err := rootAuthenticationServiceClient.UpdateUsername(ctx, req)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrConflict, err)
	})
}

func getUser(t *testing.T) *repository.UserRow {
	email := fmt.Sprintf("%s@neupaenanish.com.np", rand.Text()[:8])
	id, err := seedUser(t.Context(), email, "Password@12345", enum.UserStatusActive, false, enum.UserRoleUser)
	require.NoError(t, err)
	params := &repository.UserParams{ID: id}

	user, userErr := cfg.Repository.User(t.Context(), params)
	require.NoError(t, userErr)

	return user
}
