//go:build integration

package service_test

import (
	"testing"
	"time"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"neupaneanish.com.np/authentication/internal/repository"

	"neupaneanish.com.np/authentication/internal/errs"

	"neupaneanish.com.np/authentication/internal/enum"
	rootAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/root/authentication/v1"
)

func TestUpdateStatus(t *testing.T) {
	t.Parallel()

	t.Run("Same Status", func(t *testing.T) {
		t.Parallel()
		userID, userIDErr := seedUser(
			t.Context(),
			generateEmail(),
			"Password",
			enum.UserStatusActive,
			false,
			enum.UserRoleUser,
		)
		require.NoError(t, userIDErr)

		userParams := &repository.UserParams{ID: userID}
		user, userErr := cfg.Repository.User(t.Context(), userParams)
		require.NoError(t, userErr)

		err := seedUpdateError(t, uuid.NewV7(), userID, enum.UserRoleUser, enum.UserStatusActive, user.UpdatedAt, false)
		assert.Equal(t, errs.ErrConflict, err)
	})

	t.Run("Self Update", func(t *testing.T) {
		t.Parallel()
		adminID := uuid.NewV7()
		err := seedUpdateError(t, adminID, adminID, enum.UserRoleUser, enum.UserStatusPending, time.Now(), false)

		assert.Equal(t, errs.ErrSelfUpdate, err)
	})

	t.Run("Invalid Status", func(t *testing.T) {
		t.Parallel()
		ctx := contextWithValue(t, uuid.NewV7(), enum.UserRoleRoot)
		req := &rootAuthenticationv1.UpdateStatusRequest{
			Id:        uuid.NewV7().String(),
			Status:    "test",
			UpdatedAt: timestamppb.New(time.Now()),
		}

		res, err := rootAuthenticationServiceClient.UpdateStatus(ctx, req)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrInvalidStatus, err)
	})

	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		userID, userIDErr := seedUser(
			t.Context(),
			generateEmail(),
			"Password",
			enum.UserStatusActive,
			false,
			enum.UserRoleUser,
		)
		userParams := &repository.UserParams{ID: userID}
		user, userErr := cfg.Repository.User(t.Context(), userParams)
		require.NoError(t, userErr)

		require.NoError(t, userIDErr)

		adminID := uuid.NewV7()
		ctx := contextWithValue(t, adminID, enum.UserRoleRoot)

		req := &rootAuthenticationv1.UpdateStatusRequest{
			Id:        user.ID.String(),
			Status:    string(enum.UserStatusSuspended),
			UpdatedAt: timestamppb.New(user.UpdatedAt),
		}
		res, err := rootAuthenticationServiceClient.UpdateStatus(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, res)
	})
}
