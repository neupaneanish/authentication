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

func TestUser(t *testing.T) {
	t.Parallel()

	t.Run("No User", func(t *testing.T) {
		t.Parallel()

		ctx := contextWithValue(t, uuid.NewV7(), enum.UserRoleRoot)

		req := &rootAuthenticationv1.UserRequest{Id: uuid.NewV7().String()}
		res, err := rootAuthenticationServiceClient.User(ctx, req)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrNotFound, err)
	})

	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		ctx := contextWithValue(t, uuid.NewV7(), enum.UserRoleRoot)
		userID, userIDErr := seedUser(
			t.Context(),
			cfg.Domain.GenerateEmail(rand.Text()),
			"Password@12345",
			enum.UserStatusPending,
			false,
			enum.UserRoleUser,
		)
		require.NoError(t, userIDErr)

		req := &rootAuthenticationv1.UserRequest{Id: userID.String()}
		res, err := rootAuthenticationServiceClient.User(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, res)
		assert.Equal(t, userID.String(), res.GetId())
	})
}
