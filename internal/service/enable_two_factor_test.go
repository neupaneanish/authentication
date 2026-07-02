//go:build integration

package service_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"neupaneanish.com.np/authentication/internal/errs"
	passwordv1 "neupaneanish.com.np/authentication/internal/protobuf/common/password/v1"
	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
)

func TestEnableDisableTwoFactor(t *testing.T) {
	t.Parallel()
	oldPassword := "Password@123"
	newPassword := "Password@1234"

	t.Run("Rate Limiter", func(t *testing.T) {
		t.Parallel()

		ctx := seedSecurity(t, oldPassword)

		req := &gatewayAuthenticationv1.EnableTwoFactorRequest{
			Password: &passwordv1.Password{Value: newPassword},
		}

		for i := range 6 {
			response, responseErr := gatewayAuthenticationServiceClient.EnableTwoFactor(ctx, req)
			require.Error(t, responseErr)
			assert.Nil(t, response)

			if i < 5 {
				assert.Equal(t, errs.ErrInvalidPassword, responseErr)
			} else {
				assert.Equal(t, errs.ErrTooManyRequest, responseErr)
			}
		}
	})

	t.Run("Valid Password", func(t *testing.T) {
		t.Parallel()
		ctx := seedSecurity(t, oldPassword)

		req := &gatewayAuthenticationv1.EnableTwoFactorRequest{
			Password: &passwordv1.Password{Value: oldPassword},
		}
		response, responseErr := gatewayAuthenticationServiceClient.EnableTwoFactor(ctx, req)
		require.NoError(t, responseErr)
		assert.NotNil(t, response)
		assert.NotEmpty(t, response.GetSession())
	})
}
