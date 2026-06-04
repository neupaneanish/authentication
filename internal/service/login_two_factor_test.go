//go:build integration

package service_test

import (
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"neupaneanish.com.np/api/internal/enum"
	authv1 "neupaneanish.com.np/api/internal/protobuf/auth/v1"
	"neupaneanish.com.np/api/internal/redis"
	"neupaneanish.com.np/api/internal/repository"
	"neupaneanish.com.np/api/internal/service"
)

func TestLoginTwoFactor(t *testing.T) {
	ctx := t.Context()

	t.Run("TOTP", func(t *testing.T) {
		email := fmt.Sprintf("%s@tst.com", rand.Text())
		seed, seedErr := seedUser(ctx, email, "Password@123456")
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
		value := &service.LoginTwoFactorSession{
			Key:    session,
			ExAt:   time.Now().Add(service.SessionExpiry),
			UserID: seed,
			Role:   string(enum.UserRoleUser),
		}

		hSetErr := redis.HSet[service.LoginTwoFactorSession](
			ctx,
			service.LoginTwoFactorSessionPrefix,
			value,
			cfg.Client,
		)
		require.NoError(t, hSetErr)

		t.Run("Invalid Session", func(t *testing.T) {
			req := &authv1.LoginTwoFactorRequest{
				Session: rand.Text(),
				Code:    &authv1.LoginTwoFactorRequest_Totp{Totp: "123456"},
			}
			response, responseErr := authServiceClient.LoginTwoFactor(ctx, req)
			require.Error(t, responseErr)
			assert.Nil(t, response)
			st, _ := status.FromError(responseErr)
			assert.Equal(t, codes.Aborted, st.Code())
		})

		t.Run("Invalid Code", func(t *testing.T) {
			req := &authv1.LoginTwoFactorRequest{
				Session: session,
				Code:    &authv1.LoginTwoFactorRequest_Totp{Totp: "123456"},
			}
			response, responseErr := authServiceClient.LoginTwoFactor(ctx, req)
			require.Error(t, responseErr)
			assert.Nil(t, response)

			st, _ := status.FromError(responseErr)
			assert.Equal(t, codes.InvalidArgument, st.Code())
		})

		t.Run("Valid Session and Code", func(t *testing.T) {
			code, codeErr := totp.GenerateCode(secret.Secret, time.Now())
			require.NoError(t, codeErr)

			req := &authv1.LoginTwoFactorRequest{
				Session: session,
				Code:    &authv1.LoginTwoFactorRequest_Totp{Totp: code},
			}

			response, responseErr := authServiceClient.LoginTwoFactor(ctx, req)
			require.NoError(t, responseErr)
			assert.NotNil(t, response)
		})
	})

	t.Run("Recovery", func(t *testing.T) {
		email := fmt.Sprintf("%s@tst.com", rand.Text())
		seed, seedErr := seedUser(ctx, email, "Password@123456")
		require.NoError(t, seedErr)

		userID := uuid.MustParse(seed)

		recoveryCodes, rcErr := cfg.TwoFactor.GenerateRecoveryCodes()
		require.NoError(t, rcErr)
		assert.Equal(t, len(recoveryCodes.Plain), 10)
		assert.Equal(t, len(recoveryCodes.Hash), 10)

		session := rand.Text()
		value := &service.LoginTwoFactorSession{
			Key:    session,
			ExAt:   time.Now().Add(service.SessionExpiry),
			UserID: seed,
			Role:   string(enum.UserRoleUser),
		}

		hSetErr := redis.HSet[service.LoginTwoFactorSession](
			ctx,
			service.LoginTwoFactorSessionPrefix,
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
			req := &authv1.LoginTwoFactorRequest{
				Session: rand.Text(),
				Code:    &authv1.LoginTwoFactorRequest_Recovery{Recovery: "0123456789"},
			}
			response, responseErr := authServiceClient.LoginTwoFactor(ctx, req)
			require.Error(t, responseErr)
			assert.Nil(t, response)
			st, _ := status.FromError(responseErr)
			assert.Equal(t, codes.Aborted, st.Code())
		})

		t.Run("Invalid Code", func(t *testing.T) {
			req := &authv1.LoginTwoFactorRequest{
				Session: session,
				Code:    &authv1.LoginTwoFactorRequest_Recovery{Recovery: "0123456789"},
			}
			response, responseErr := authServiceClient.LoginTwoFactor(ctx, req)
			require.Error(t, responseErr)
			assert.Nil(t, response)
			st, _ := status.FromError(responseErr)
			assert.Equal(t, codes.InvalidArgument, st.Code())
		})

		t.Run("Valid session and Code", func(t *testing.T) {
			recovery := strings.ReplaceAll(recoveryCodes.Plain[0], "-", "")

			req := &authv1.LoginTwoFactorRequest{
				Session: session,
				Code:    &authv1.LoginTwoFactorRequest_Recovery{Recovery: recovery},
			}
			response, responseErr := authServiceClient.LoginTwoFactor(ctx, req)
			require.NoError(t, responseErr)
			assert.NotNil(t, response)
		})

		t.Run("Valid session and Reuse Code", func(t *testing.T) {
			s := rand.Text()
			data := &service.LoginTwoFactorSession{
				Key:    s,
				ExAt:   time.Now().Add(service.SessionExpiry),
				UserID: seed,
				Role:   string(enum.UserRoleUser),
			}

			setErr := redis.HSet[service.LoginTwoFactorSession](
				ctx,
				service.LoginTwoFactorSessionPrefix,
				data,
				cfg.Client,
			)
			require.NoError(t, setErr)

			recovery := strings.ReplaceAll(recoveryCodes.Plain[0], "-", "")

			req := &authv1.LoginTwoFactorRequest{
				Session: s,
				Code:    &authv1.LoginTwoFactorRequest_Recovery{Recovery: recovery},
			}
			response, responseErr := authServiceClient.LoginTwoFactor(ctx, req)
			require.Error(t, responseErr)
			assert.Nil(t, response)

			st, _ := status.FromError(responseErr)
			assert.Equal(t, codes.InvalidArgument, st.Code())
		})
	})

	t.Run("Rate Limiter", func(t *testing.T) {
		session := rand.Text()

		t.Run("Allowed", func(t *testing.T) {
			for range 5 {
				req := &authv1.LoginTwoFactorRequest{
					Session: session,
					Code:    &authv1.LoginTwoFactorRequest_Totp{Totp: "123456"},
				}
				response, responseErr := authServiceClient.LoginTwoFactor(ctx, req)
				require.Error(t, responseErr)
				assert.Nil(t, response)

				st, _ := status.FromError(responseErr)
				assert.Equal(t, codes.Aborted, st.Code())
			}
		})

		t.Run("Blocked", func(t *testing.T) {
			req := &authv1.LoginTwoFactorRequest{
				Session: session,
				Code:    &authv1.LoginTwoFactorRequest_Totp{Totp: "123456"},
			}
			response, responseErr := authServiceClient.LoginTwoFactor(ctx, req)
			require.Error(t, responseErr)
			assert.Nil(t, response)

			st, _ := status.FromError(responseErr)
			assert.Equal(t, codes.ResourceExhausted, st.Code())
		})
	})

	t.Run("Missing Code", func(t *testing.T) {
		session := rand.Text()
		userID := uuid.NewString()

		value := &service.LoginTwoFactorSession{
			Key:    session,
			ExAt:   time.Now().Add(service.SessionExpiry),
			UserID: userID,
			Role:   string(enum.UserRoleUser),
		}

		hSetErr := redis.HSet[service.LoginTwoFactorSession](
			ctx,
			service.LoginTwoFactorSessionPrefix,
			value,
			cfg.Client,
		)

		require.NoError(t, hSetErr)
		req := &authv1.LoginTwoFactorRequest{
			Session: session,
			Code:    nil,
		}

		response, responseErr := authServiceClient.LoginTwoFactor(ctx, req)

		require.Error(t, responseErr)
		assert.Nil(t, response)

		st, _ := status.FromError(responseErr)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("No User in TOTP DB", func(t *testing.T) {
		session := rand.Text()
		userID := uuid.NewString()

		value := &service.LoginTwoFactorSession{
			Key:    session,
			ExAt:   time.Now().Add(service.SessionExpiry),
			UserID: userID,
			Role:   string(enum.UserRoleUser),
		}

		hSetErr := redis.HSet[service.LoginTwoFactorSession](
			ctx,
			service.LoginTwoFactorSessionPrefix,
			value,
			cfg.Client,
		)

		require.NoError(t, hSetErr)
		req := &authv1.LoginTwoFactorRequest{
			Session: session,
			Code:    &authv1.LoginTwoFactorRequest_Totp{Totp: "123456"},
		}

		response, responseErr := authServiceClient.LoginTwoFactor(ctx, req)

		require.Error(t, responseErr)
		assert.Nil(t, response)

		st, _ := status.FromError(responseErr)
		assert.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("No User in Recovery DB", func(t *testing.T) {
		session := rand.Text()
		userID := uuid.NewString()

		value := &service.LoginTwoFactorSession{
			Key:    session,
			ExAt:   time.Now().Add(service.SessionExpiry),
			UserID: userID,
			Role:   string(enum.UserRoleUser),
		}

		hSetErr := redis.HSet[service.LoginTwoFactorSession](
			ctx,
			service.LoginTwoFactorSessionPrefix,
			value,
			cfg.Client,
		)

		require.NoError(t, hSetErr)
		req := &authv1.LoginTwoFactorRequest{
			Session: session,
			Code:    &authv1.LoginTwoFactorRequest_Recovery{Recovery: "0123456789"},
		}

		response, responseErr := authServiceClient.LoginTwoFactor(ctx, req)

		require.Error(t, responseErr)
		assert.Nil(t, response)

		st, _ := status.FromError(responseErr)
		assert.Equal(t, codes.NotFound, st.Code())
	})
}
