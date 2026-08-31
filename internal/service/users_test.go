//go:build integration

package service_test

import (
	"crypto/rand"
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"neupaneanish.com.np/authentication/internal/enum"
	"neupaneanish.com.np/authentication/internal/errs"
	rootAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/root/authentication/v1"
)

func TestUsers(t *testing.T) {
	t.Parallel()

	t.Run("No Context", func(t *testing.T) {
		t.Parallel()
		req := &rootAuthenticationv1.UsersRequest{}
		res, err := rootAuthenticationServiceClient.Users(t.Context(), req)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrUnauthenticated, err)
	})

	t.Run("No Root user", func(t *testing.T) {
		t.Parallel()
		ctx := contextWithValue(t, uuid.NewV7(), enum.UserRoleUser)
		req := &rootAuthenticationv1.UsersRequest{}
		res, err := rootAuthenticationServiceClient.Users(ctx, req)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrPermissionDenied, err)
	})

	// No Users are not tested because of shared database and it impossible to test

	//t.Run("No Users", func(t *testing.T) {
	//	t.Parallel()
	//	ctx := contextWithValue(t, uuid.NewV7(), enum.UserRoleRoot)
	//	req := &rootAuthenticationv1.UsersRequest{}
	//	res, err := rootAuthenticationServiceClient.Users(ctx, req)
	//	require.Error(t, err)
	//	assert.Nil(t, res)
	//	assert.Equal(t, errs.ErrUnauthenticated, err)
	//})

	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		rootUser, rootUserErr := seedUser(
			t.Context(),
			cfg.Domain.GenerateEmail(rand.Text()),
			"Password@1345",
			enum.UserStatusActive,
			true,
			enum.UserRoleRoot,
		)
		require.NoError(t, rootUserErr)
		_, userErr := seedUser(
			t.Context(),
			cfg.Domain.GenerateEmail(rand.Text()),
			"Password@12345",
			enum.UserStatusPending,
			false,
			enum.UserRoleUser,
		)
		require.NoError(t, userErr)
		ctx := contextWithValue(t, rootUser, enum.UserRoleRoot)
		req := &rootAuthenticationv1.UsersRequest{}
		res, err := rootAuthenticationServiceClient.Users(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, res)
		assert.GreaterOrEqual(t, len(res.GetUsers()), 2)
	})
}
