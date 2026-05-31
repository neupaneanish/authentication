//go:build integration

package service_test

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	authv1 "neupaneanish.com.np/api/internal/protobuf/auth/v1"
)

func TestForgetPassword(t *testing.T) {
	t.Parallel()

	t.Run("Unregister email", func(t *testing.T) {
		t.Parallel()
		email := fmt.Sprintf("%s@test.com", rand.Text())
		req := &authv1.ForgetPasswordRequest{Email: email}

		response, err := authServiceClient.ForgetPassword(t.Context(), req)
		require.NoError(t, err)
		assert.NotNil(t, response)
	})

	t.Run("Register email", func(t *testing.T) {
		t.Parallel()
		_, seedErr := seedUser(t.Context(), "forgetPassword@test.com", "forgetPassword@123456")
		require.NoError(t, seedErr)

		email := fmt.Sprintf("%s@test.com", rand.Text())
		req := &authv1.ForgetPasswordRequest{Email: email}

		response, err := authServiceClient.ForgetPassword(t.Context(), req)
		require.NoError(t, err)
		assert.NotNil(t, response)
	})

	t.Run("Rate limiter", func(t *testing.T) {
		email := fmt.Sprintf("%s@test.com", rand.Text())
		t.Run("Allowed", func(t *testing.T) {
			for range 5 {
				req := &authv1.ForgetPasswordRequest{Email: email}
				response, err := authServiceClient.ForgetPassword(t.Context(), req)
				require.NoError(t, err)
				assert.NotNil(t, response)
			}
		})

		t.Run("Blocked", func(t *testing.T) {
			req := &authv1.ForgetPasswordRequest{Email: email}
			response, err := authServiceClient.ForgetPassword(t.Context(), req)
			require.Error(t, err)
			assert.Nil(t, response)

			st, _ := status.FromError(err)
			assert.Equal(t, codes.ResourceExhausted, st.Code())
		})
	})
}
