//go:build integration

package service_test

import (
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"neupaneanish.com.np/authentication/internal/enum"
	"neupaneanish.com.np/authentication/internal/errs"
	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"
	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/internal/repository"
	"neupaneanish.com.np/authentication/internal/utils"
)

func TestLoginTwoFactor(t *testing.T) {
	t.Parallel()

	t.Run("TOTP Success", func(t *testing.T) {
		t.Parallel()
		session, secret, _, _ := seedTwoFactorLogin(t)

		code, codeErr := totp.GenerateCode(secret, time.Now())
		require.NoError(t, codeErr)

		req := &externalAuthenticationv1.LoginTwoFactorRequest{
			Session: session,
			Code:    &externalAuthenticationv1.LoginTwoFactorRequest_Totp{Totp: code},
		}

		response, responseErr := externalAuthenticationServiceClient.LoginTwoFactor(t.Context(), req)
		require.NoError(t, responseErr)
		assert.NotNil(t, response)
	})

	t.Run("Invalid Session", func(t *testing.T) {
		t.Parallel()

		req := &externalAuthenticationv1.LoginTwoFactorRequest{
			Session: rand.Text(),
			Code:    &externalAuthenticationv1.LoginTwoFactorRequest_Totp{Totp: "123456"},
		}
		response, responseErr := externalAuthenticationServiceClient.LoginTwoFactor(t.Context(), req)
		require.Error(t, responseErr)
		assert.Nil(t, response)

		assert.Equal(t, errs.ErrSessionExpired, responseErr)
	})

	t.Run("Invalid TOTP Code", func(t *testing.T) {
		t.Parallel()

		session, _, _, _ := seedTwoFactorLogin(t)
		req := &externalAuthenticationv1.LoginTwoFactorRequest{
			Session: session,
			Code:    &externalAuthenticationv1.LoginTwoFactorRequest_Totp{Totp: "123456"},
		}
		response, responseErr := externalAuthenticationServiceClient.LoginTwoFactor(t.Context(), req)
		require.Error(t, responseErr)
		assert.Nil(t, response)

		assert.Equal(t, errs.ErrInvalidCode, responseErr)
	})

	t.Run("Recovery Invalid Session", func(t *testing.T) {
		t.Parallel()
		req := &externalAuthenticationv1.LoginTwoFactorRequest{
			Session: rand.Text(),
			Code:    &externalAuthenticationv1.LoginTwoFactorRequest_Recovery{Recovery: "0123456789"},
		}
		response, responseErr := externalAuthenticationServiceClient.LoginTwoFactor(t.Context(), req)
		require.Error(t, responseErr)
		assert.Nil(t, response)

		assert.Equal(t, errs.ErrSessionExpired, responseErr)
	})

	t.Run("Invalid Recovery Code", func(t *testing.T) {
		t.Parallel()

		session, _, _, _ := seedTwoFactorLogin(t)

		req := &externalAuthenticationv1.LoginTwoFactorRequest{
			Session: session,
			Code:    &externalAuthenticationv1.LoginTwoFactorRequest_Recovery{Recovery: "0123456789"},
		}
		response, responseErr := externalAuthenticationServiceClient.LoginTwoFactor(t.Context(), req)
		require.Error(t, responseErr)
		assert.Nil(t, response)

		assert.Equal(t, errs.ErrInvalidCode, responseErr)
	})

	t.Run("Recovery Success", func(t *testing.T) {
		t.Parallel()

		session, _, recoveryCodes, userID := seedTwoFactorLogin(t)
		recovery := strings.ReplaceAll(recoveryCodes[0], "-", "")

		req := &externalAuthenticationv1.LoginTwoFactorRequest{
			Session: session,
			Code:    &externalAuthenticationv1.LoginTwoFactorRequest_Recovery{Recovery: recovery},
		}
		response, responseErr := externalAuthenticationServiceClient.LoginTwoFactor(t.Context(), req)
		require.NoError(t, responseErr)
		assert.NotNil(t, response)

		newSession := rand.Text()
		data := &utils.LoginTwoFactorSession{
			Key:    newSession,
			ExAt:   time.Now().Add(utils.SessionExpiry),
			UserID: userID,
			Role:   string(enum.UserRoleUser),
		}

		setErr := redis.HSet[utils.LoginTwoFactorSession](
			t.Context(),
			utils.LoginTwoFactorSessionPrefix,
			data,
			cfg.Client,
		)
		require.NoError(t, setErr)

		newReq := &externalAuthenticationv1.LoginTwoFactorRequest{
			Session: newSession,
			Code:    &externalAuthenticationv1.LoginTwoFactorRequest_Recovery{Recovery: recovery},
		}
		newResponse, newResponseErr := externalAuthenticationServiceClient.LoginTwoFactor(t.Context(), newReq)
		require.Error(t, newResponseErr)
		assert.Nil(t, newResponse)

		assert.Equal(t, errs.ErrInvalidCode, newResponseErr)
	})

	t.Run("Rate Limiter Session", func(t *testing.T) {
		t.Parallel()

		session := rand.Text()
		for i := range 6 {
			req := &externalAuthenticationv1.LoginTwoFactorRequest{
				Session: session,
				Code:    &externalAuthenticationv1.LoginTwoFactorRequest_Totp{Totp: "123456"},
			}
			response, responseErr := externalAuthenticationServiceClient.LoginTwoFactor(t.Context(), req)
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
		session := rand.Text()

		value := &utils.LoginTwoFactorSession{
			Key:    session,
			ExAt:   time.Now().Add(utils.SessionExpiry),
			UserID: userID,
			Role:   string(enum.UserRoleUser),
		}

		hSetErr := redis.HSet[utils.LoginTwoFactorSession](
			t.Context(),
			utils.LoginTwoFactorSessionPrefix,
			value,
			cfg.Client,
		)

		require.NoError(t, hSetErr)

		for i := range 6 {
			if i < 5 {
				req := &externalAuthenticationv1.LoginTwoFactorRequest{
					Session: session,
					Code:    nil,
				}
				response, responseErr := externalAuthenticationServiceClient.LoginTwoFactor(t.Context(), req)
				require.Error(t, responseErr)
				assert.Nil(t, response)
				assert.Equal(t, errs.ErrInvalidCode, responseErr)
			} else {
				newSession := rand.Text()

				newValue := &utils.LoginTwoFactorSession{
					Key:    newSession,
					ExAt:   time.Now().Add(utils.SessionExpiry),
					UserID: userID,
					Role:   string(enum.UserRoleUser),
				}

				newHSetErr := redis.HSet[utils.LoginTwoFactorSession](
					t.Context(),
					utils.LoginTwoFactorSessionPrefix,
					newValue,
					cfg.Client,
				)

				require.NoError(t, newHSetErr)

				req := &externalAuthenticationv1.LoginTwoFactorRequest{
					Session: newSession,
					Code:    nil,
				}
				response, responseErr := externalAuthenticationServiceClient.LoginTwoFactor(t.Context(), req)
				require.Error(t, responseErr)
				assert.Nil(t, response)
				assert.Equal(t, errs.ErrTooManyRequest, responseErr)
			}
		}
	})

	t.Run("No User in TOTP DB", func(t *testing.T) {
		t.Parallel()
		session := rand.Text()
		userID := uuid.NewString()

		value := &utils.LoginTwoFactorSession{
			Key:    session,
			ExAt:   time.Now().Add(utils.SessionExpiry),
			UserID: userID,
			Role:   string(enum.UserRoleUser),
		}

		hSetErr := redis.HSet[utils.LoginTwoFactorSession](
			t.Context(),
			utils.LoginTwoFactorSessionPrefix,
			value,
			cfg.Client,
		)

		require.NoError(t, hSetErr)
		req := &externalAuthenticationv1.LoginTwoFactorRequest{
			Session: session,
			Code:    &externalAuthenticationv1.LoginTwoFactorRequest_Totp{Totp: "123456"},
		}

		response, responseErr := externalAuthenticationServiceClient.LoginTwoFactor(t.Context(), req)

		require.Error(t, responseErr)
		assert.Nil(t, response)

		assert.Equal(t, errs.ErrSessionExpired, responseErr)
	})

	t.Run("No User in Recovery DB", func(t *testing.T) {
		t.Parallel()

		session := rand.Text()
		userID := uuid.NewString()

		value := &utils.LoginTwoFactorSession{
			Key:    session,
			ExAt:   time.Now().Add(utils.SessionExpiry),
			UserID: userID,
			Role:   string(enum.UserRoleUser),
		}

		hSetErr := redis.HSet[utils.LoginTwoFactorSession](
			t.Context(),
			utils.LoginTwoFactorSessionPrefix,
			value,
			cfg.Client,
		)

		require.NoError(t, hSetErr)
		req := &externalAuthenticationv1.LoginTwoFactorRequest{
			Session: session,
			Code:    &externalAuthenticationv1.LoginTwoFactorRequest_Recovery{Recovery: "0123456789"},
		}

		response, responseErr := externalAuthenticationServiceClient.LoginTwoFactor(t.Context(), req)

		require.Error(t, responseErr)
		assert.Nil(t, response)

		assert.Equal(t, errs.ErrSessionExpired, responseErr)
	})
}

func seedTwoFactorLogin(t *testing.T) (string, string, []string, string) {
	t.Helper()

	email := cfg.Domain.GenerateEmail(rand.Text())
	userIDStr, seedErr := seedUser(t.Context(), email, "Password@123456", enum.UserStatusActive, true)
	require.NoError(t, seedErr)

	userID := uuid.MustParse(userIDStr)
	secret, secretErr := cfg.TwoFactor.Generate(email)
	require.NoError(t, secretErr)

	params := &repository.CreateTwoFactorParams{
		UserID:    userID,
		Secret:    secret.Encrypt,
		CreatedBy: userID,
		UpdatedBy: userID,
	}

	row, rowErr := cfg.Repository.CreateTwoFactor(t.Context(), params)
	require.NoError(t, rowErr)
	assert.GreaterOrEqual(t, row.RowsAffected(), int64(1))

	recoveryCodes, rcErr := cfg.TwoFactor.GenerateRecoveryCodes()
	require.NoError(t, rcErr)
	assert.Len(t, recoveryCodes.Plain, 10)
	assert.Len(t, recoveryCodes.Hash, 10)

	recoveryCodesRows := make([]*repository.CreateRecoveryCodesParams, 0, len(recoveryCodes.Hash))
	for _, hash := range recoveryCodes.Hash {
		recoveryCodesRows = append(recoveryCodesRows, &repository.CreateRecoveryCodesParams{
			UserID:    userID,
			Code:      hash,
			CreatedBy: userID,
			UpdatedBy: userID,
		})
	}

	recoveryRow, recoveryRowErr := cfg.Repository.CreateRecoveryCodes(t.Context(), recoveryCodesRows)
	require.NoError(t, recoveryRowErr)
	assert.Equal(t, int64(10), recoveryRow)

	session := rand.Text()
	value := &utils.LoginTwoFactorSession{
		Key:    session,
		ExAt:   time.Now().Add(utils.SessionExpiry),
		UserID: userIDStr,
		Role:   string(enum.UserRoleUser),
	}

	hSetErr := redis.HSet[utils.LoginTwoFactorSession](
		t.Context(),
		utils.LoginTwoFactorSessionPrefix,
		value,
		cfg.Client,
	)
	require.NoError(t, hSetErr)

	return session, secret.Secret, recoveryCodes.Plain, userIDStr
}
