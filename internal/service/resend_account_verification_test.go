//go:build integration

package service_test

import (
	"crypto/rand"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"neupaneanish.com.np/authentication/internal/enum"
	"neupaneanish.com.np/authentication/internal/errs"
	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"
)

func TestResendAccountVerification(t *testing.T) {
	t.Parallel()

	t.Run("Rate Limiter Session", func(t *testing.T) {
		t.Parallel()
		session := rand.Text()
		req := &externalAuthenticationv1.ResendAccountVerificationRequest{Session: session}

		for i := range 6 {
			response, responseErr := externalAuthenticationServiceClient.ResendAccountVerification(t.Context(), req)
			require.Error(t, responseErr)
			assert.Nil(t, response)
			if i < 5 {
				assert.Equal(t, errs.ErrSessionExpired, responseErr)
			} else {
				assert.Equal(t, errs.ErrTooManyRequest, responseErr)
			}
		}
	})

	t.Run("Rate Limiter UserID", func(t *testing.T) {
		t.Parallel()
		userID := uuid.NewString()

		for i := range 6 {
			session := rand.Text()
			seedAccountVerificationSession(
				t,
				session,
				userID,
				"test",
				enum.MethodRegister,
				"12345678",
				false,
				cfg.Domain.GenerateEmail(session),
				cfg.Client,
			)
			req := &externalAuthenticationv1.ResendAccountVerificationRequest{Session: session}
			response, responseErr := externalAuthenticationServiceClient.ResendAccountVerification(t.Context(), req)

			if i < 5 {
				assert.NoError(t, responseErr)
				assert.NotNil(t, response)
			} else {
				require.Error(t, responseErr)
				assert.Nil(t, response)
				assert.Equal(t, errs.ErrTooManyRequest, responseErr)
			}
		}
	})
}
