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
	ctx := t.Context()

	t.Run("TOTP", func(t *testing.T) {
		email := cfg.Domain.GenerateEmail(rand.Text())
		seed, seedErr := seedUser(ctx, email, "Password@123456", enum.UserStatusActive, true)
		require.NoError(t, seedErr)

		userID := uuid.MustParse(seed)
		secret, secretErr := cfg.TwoFactor.Generate(email)
		require.NoError(t, secretErr)

		secretEncrypt, secretEncryptErr := cfg.TwoFactor.Encrypt(secret.Secret)
		require.NoError(t, secretEncryptErr)

		params := &repository.CreateTwoFactorParams{
			UserID:    userID,
			Secret:    secretEncrypt,
			CreatedBy: userID,
			UpdatedBy: userID,
		}

		row, rowErr := cfg.Repository.CreateTwoFactor(ctx, params)
		require.NoError(t, rowErr)
		assert.GreaterOrEqual(t, row.RowsAffected(), int64(1))

		session := rand.Text()
		value := &utils.LoginTwoFactorSession{
			Key:    session,
			ExAt:   time.Now().Add(utils.SessionExpiry),
			UserID: seed,
			Role:   string(enum.UserRoleUser),
		}

		hSetErr := redis.HSet[utils.LoginTwoFactorSession](
			ctx,
			utils.LoginTwoFactorSessionPrefix,
			value,
			cfg.Client,
		)
		require.NoError(t, hSetErr)

		t.Run("Invalid Session", func(t *testing.T) {
			req := &externalAuthenticationv1.LoginTwoFactorRequest{
				Session: rand.Text(),
				Code:    &externalAuthenticationv1.LoginTwoFactorRequest_Totp{Totp: "123456"},
			}
			response, responseErr := externalAuthenticationServiceClient.LoginTwoFactor(ctx, req)
			require.Error(t, responseErr)
			assert.Nil(t, response)

			assert.Equal(t, errs.ErrSessionExpired, responseErr)
		})

		t.Run("Invalid Code", func(t *testing.T) {
			req := &externalAuthenticationv1.LoginTwoFactorRequest{
				Session: session,
				Code:    &externalAuthenticationv1.LoginTwoFactorRequest_Totp{Totp: "123456"},
			}
			response, responseErr := externalAuthenticationServiceClient.LoginTwoFactor(ctx, req)
			require.Error(t, responseErr)
			assert.Nil(t, response)

			assert.Equal(t, errs.ErrInvalidCode, responseErr)
		})

		t.Run("Valid Session and Code", func(t *testing.T) {
			code, codeErr := totp.GenerateCode(secret.Secret, time.Now())
			require.NoError(t, codeErr)

			req := &externalAuthenticationv1.LoginTwoFactorRequest{
				Session: session,
				Code:    &externalAuthenticationv1.LoginTwoFactorRequest_Totp{Totp: code},
			}

			response, responseErr := externalAuthenticationServiceClient.LoginTwoFactor(ctx, req)
			require.NoError(t, responseErr)
			assert.NotNil(t, response)
		})
	})

	t.Run("Recovery", func(t *testing.T) {
		email := cfg.Domain.GenerateEmail(rand.Text())
		seed, seedErr := seedUser(ctx, email, "Password@123456", enum.UserStatusActive, true)
		require.NoError(t, seedErr)

		userID := uuid.MustParse(seed)

		recoveryCodes, rcErr := cfg.TwoFactor.GenerateRecoveryCodes()
		require.NoError(t, rcErr)
		assert.Equal(t, len(recoveryCodes.Plain), 10)
		assert.Equal(t, len(recoveryCodes.Hash), 10)

		session := rand.Text()
		value := &utils.LoginTwoFactorSession{
			Key:    session,
			ExAt:   time.Now().Add(utils.SessionExpiry),
			UserID: seed,
			Role:   string(enum.UserRoleUser),
		}

		hSetErr := redis.HSet[utils.LoginTwoFactorSession](
			ctx,
			utils.LoginTwoFactorSessionPrefix,
			value,
			cfg.Client,
		)
		require.NoError(t, hSetErr)

		recoveryCodesRows := make([]*repository.CreateRecoveryCodesParams, 0, len(recoveryCodes.Hash))
		for _, hash := range recoveryCodes.Hash {
			recoveryCodesRows = append(recoveryCodesRows, &repository.CreateRecoveryCodesParams{
				UserID:    userID,
				Code:      hash,
				CreatedBy: userID,
				UpdatedBy: userID,
			})
		}

		row, rowErr := cfg.Repository.CreateRecoveryCodes(ctx, recoveryCodesRows)
		require.NoError(t, rowErr)
		assert.Equal(t, row, int64(10))

		t.Run("Invalid Session", func(t *testing.T) {
			req := &externalAuthenticationv1.LoginTwoFactorRequest{
				Session: rand.Text(),
				Code:    &externalAuthenticationv1.LoginTwoFactorRequest_Recovery{Recovery: "0123456789"},
			}
			response, responseErr := externalAuthenticationServiceClient.LoginTwoFactor(ctx, req)
			require.Error(t, responseErr)
			assert.Nil(t, response)

			assert.Equal(t, errs.ErrSessionExpired, responseErr)
		})

		t.Run("Invalid Code", func(t *testing.T) {
			req := &externalAuthenticationv1.LoginTwoFactorRequest{
				Session: session,
				Code:    &externalAuthenticationv1.LoginTwoFactorRequest_Recovery{Recovery: "0123456789"},
			}
			response, responseErr := externalAuthenticationServiceClient.LoginTwoFactor(ctx, req)
			require.Error(t, responseErr)
			assert.Nil(t, response)

			assert.Equal(t, errs.ErrInvalidCode, responseErr)
		})

		t.Run("Valid session and Code", func(t *testing.T) {
			recovery := strings.ReplaceAll(recoveryCodes.Plain[0], "-", "")

			req := &externalAuthenticationv1.LoginTwoFactorRequest{
				Session: session,
				Code:    &externalAuthenticationv1.LoginTwoFactorRequest_Recovery{Recovery: recovery},
			}
			response, responseErr := externalAuthenticationServiceClient.LoginTwoFactor(ctx, req)
			require.NoError(t, responseErr)
			assert.NotNil(t, response)
		})

		t.Run("Valid session and Reuse Code", func(t *testing.T) {
			s := rand.Text()
			data := &utils.LoginTwoFactorSession{
				Key:    s,
				ExAt:   time.Now().Add(utils.SessionExpiry),
				UserID: seed,
				Role:   string(enum.UserRoleUser),
			}

			setErr := redis.HSet[utils.LoginTwoFactorSession](
				ctx,
				utils.LoginTwoFactorSessionPrefix,
				data,
				cfg.Client,
			)
			require.NoError(t, setErr)

			recovery := strings.ReplaceAll(recoveryCodes.Plain[0], "-", "")

			req := &externalAuthenticationv1.LoginTwoFactorRequest{
				Session: s,
				Code:    &externalAuthenticationv1.LoginTwoFactorRequest_Recovery{Recovery: recovery},
			}
			response, responseErr := externalAuthenticationServiceClient.LoginTwoFactor(ctx, req)
			require.Error(t, responseErr)
			assert.Nil(t, response)

			assert.Equal(t, errs.ErrInvalidCode, responseErr)
		})
	})

	t.Run("Rate Limiter Session", func(t *testing.T) {
		t.Parallel()
		session := rand.Text()
		for i := range 6 {
			req := &externalAuthenticationv1.LoginTwoFactorRequest{
				Session: session,
				Code:    &externalAuthenticationv1.LoginTwoFactorRequest_Totp{Totp: "123456"},
			}
			response, responseErr := externalAuthenticationServiceClient.LoginTwoFactor(ctx, req)
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
			ctx,
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
				response, responseErr := externalAuthenticationServiceClient.LoginTwoFactor(ctx, req)
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
					ctx,
					utils.LoginTwoFactorSessionPrefix,
					newValue,
					cfg.Client,
				)

				require.NoError(t, newHSetErr)

				req := &externalAuthenticationv1.LoginTwoFactorRequest{
					Session: newSession,
					Code:    nil,
				}
				response, responseErr := externalAuthenticationServiceClient.LoginTwoFactor(ctx, req)
				require.Error(t, responseErr)
				assert.Nil(t, response)
				assert.Equal(t, errs.ErrTooManyRequest, responseErr)
			}
		}
	})

	t.Run("No User in TOTP DB", func(t *testing.T) {
		session := rand.Text()
		userID := uuid.NewString()

		value := &utils.LoginTwoFactorSession{
			Key:    session,
			ExAt:   time.Now().Add(utils.SessionExpiry),
			UserID: userID,
			Role:   string(enum.UserRoleUser),
		}

		hSetErr := redis.HSet[utils.LoginTwoFactorSession](
			ctx,
			utils.LoginTwoFactorSessionPrefix,
			value,
			cfg.Client,
		)

		require.NoError(t, hSetErr)
		req := &externalAuthenticationv1.LoginTwoFactorRequest{
			Session: session,
			Code:    &externalAuthenticationv1.LoginTwoFactorRequest_Totp{Totp: "123456"},
		}

		response, responseErr := externalAuthenticationServiceClient.LoginTwoFactor(ctx, req)

		require.Error(t, responseErr)
		assert.Nil(t, response)

		assert.Equal(t, errs.ErrNotFound, responseErr)
	})

	t.Run("No User in Recovery DB", func(t *testing.T) {
		session := rand.Text()
		userID := uuid.NewString()

		value := &utils.LoginTwoFactorSession{
			Key:    session,
			ExAt:   time.Now().Add(utils.SessionExpiry),
			UserID: userID,
			Role:   string(enum.UserRoleUser),
		}

		hSetErr := redis.HSet[utils.LoginTwoFactorSession](
			ctx,
			utils.LoginTwoFactorSessionPrefix,
			value,
			cfg.Client,
		)

		require.NoError(t, hSetErr)
		req := &externalAuthenticationv1.LoginTwoFactorRequest{
			Session: session,
			Code:    &externalAuthenticationv1.LoginTwoFactorRequest_Recovery{Recovery: "0123456789"},
		}

		response, responseErr := externalAuthenticationServiceClient.LoginTwoFactor(ctx, req)

		require.Error(t, responseErr)
		assert.Nil(t, response)

		assert.Equal(t, errs.ErrNotFound, responseErr)
	})
}
