//go:build integration

package service_test

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"neupaneanish.com.np/authentication/internal/errs"
	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"
	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/internal/utils"
)

func TestVerification(t *testing.T) {
	t.Parallel()

	t.Run("Invalid session", func(t *testing.T) {
		t.Parallel()

		req := &externalAuthenticationv1.VerificationRequest{Session: rand.Text(), Code: "12345678"}

		response, responseErr := externalAuthenticationServiceClient.Verification(t.Context(), req)
		require.Error(t, responseErr)
		assert.Nil(t, response)

		assert.Equal(t, errs.ErrSessionExpired, responseErr)
	})

	t.Run("Valid session invalid code", func(t *testing.T) {
		t.Parallel()
		session, _ := seedVerification(t)
		req := &externalAuthenticationv1.VerificationRequest{Session: session, Code: "12345678"}

		response, responseErr := externalAuthenticationServiceClient.Verification(t.Context(), req)
		require.Error(t, responseErr)
		assert.Nil(t, response)

		assert.Equal(t, errs.ErrInvalidCode, responseErr)
	})

	t.Run("Valid session and code", func(t *testing.T) {
		t.Parallel()
		session, code := seedVerification(t)
		req := &externalAuthenticationv1.VerificationRequest{Session: session, Code: code}

		response, responseErr := externalAuthenticationServiceClient.Verification(t.Context(), req)
		require.NoError(t, responseErr)
		assert.NotNil(t, response)
	})

	t.Run("Rate limiter Session", func(t *testing.T) {
		t.Parallel()

		session := rand.Text()

		req := &externalAuthenticationv1.VerificationRequest{Session: session, Code: "12345678"}
		for i := range 5 {
			response, responseErr := externalAuthenticationServiceClient.Verification(t.Context(), req)
			require.Error(t, responseErr)
			assert.Nil(t, response)
			if i < 5 {
				assert.Equal(t, errs.ErrSessionExpired, responseErr)
			} else {
				assert.Equal(t, errs.ErrTooManyRequest, responseErr)
			}
		}
	})

	t.Run("Rate limiter UserID", func(t *testing.T) {
		t.Parallel()

		session := rand.Text()
		code := "A1B2C3D4"
		userID := uuid.NewString()

		data := &utils.ForgetPasswordSession{
			Key:    session,
			ExAt:   time.Now().Add(utils.SessionExpiry),
			UserID: userID,
			Code:   code,
		}

		hSetErr := redis.HSet[utils.ForgetPasswordSession](
			t.Context(),
			utils.ForgetPasswordSessionPrefix,
			data,
			cfg.Client,
		)
		require.NoError(t, hSetErr)

		for i := range 6 {
			if i < 5 {
				req := &externalAuthenticationv1.VerificationRequest{Session: session, Code: "12345678"}
				response, responseErr := externalAuthenticationServiceClient.Verification(t.Context(), req)
				require.Error(t, responseErr)
				assert.Nil(t, response)
				assert.Equal(t, errs.ErrInvalidCode, responseErr)
			} else {
				newSession := rand.Text()
				newData := &utils.ForgetPasswordSession{
					Key:    newSession,
					ExAt:   time.Now().Add(utils.SessionExpiry),
					UserID: userID,
					Code:   code,
				}

				newHSetErr := redis.HSet[utils.ForgetPasswordSession](
					t.Context(),
					utils.ForgetPasswordSessionPrefix,
					newData,
					cfg.Client,
				)

				require.NoError(t, newHSetErr)
				req := &externalAuthenticationv1.VerificationRequest{Session: newSession, Code: "12345678"}
				response, responseErr := externalAuthenticationServiceClient.Verification(t.Context(), req)
				require.Error(t, responseErr)
				assert.Nil(t, response)
				assert.Equal(t, errs.ErrTooManyRequest, responseErr)
			}
		}
	})
}

func seedVerification(t *testing.T) (string, string) {
	t.Helper()
	session := rand.Text()
	code := "A1B2C3D4"

	data := &utils.ForgetPasswordSession{
		Key:    session,
		ExAt:   time.Now().Add(utils.SessionExpiry),
		UserID: uuid.NewString(),
		Code:   code,
	}

	hSetErr := redis.HSet[utils.ForgetPasswordSession](
		t.Context(),
		utils.ForgetPasswordSessionPrefix,
		data,
		cfg.Client,
	)
	require.NoError(t, hSetErr)
	return session, code
}
