//go:build e2e

package service_test

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"neupaneanish.com.np/api/internal/enum"
	authv1 "neupaneanish.com.np/api/internal/protobuf/auth/v1"
	passwordv1 "neupaneanish.com.np/api/internal/protobuf/common/password/v1"
	"neupaneanish.com.np/api/internal/redis"
	"neupaneanish.com.np/api/internal/utils"
)

func TestForgetPasswordE2E(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	email := cfg.Domain.GenerateEmail(rand.Text())
	oldPassword := "Test@123456"
	newPassword := "Test@1234567"

	seedID, seedErr := seedUser(ctx, email, oldPassword, enum.UserStatusActive, true)
	require.NoError(t, seedErr)
	assert.NotNil(t, seedID)

	forgetPasswordParams := &authv1.ForgetPasswordRequest{Email: email}
	forgetPasswordRes, forgetPasswordResErr := authServiceClient.ForgetPassword(ctx, forgetPasswordParams)
	require.NoError(t, forgetPasswordResErr)

	hGet, hGetErr := redis.HGet[utils.ForgetPasswordSession](
		ctx,
		utils.ForgetPasswordSessionPrefix,
		forgetPasswordRes.GetSession(),
		cfg.Client,
	)
	require.NoError(t, hGetErr)

	verificationParams := &authv1.VerificationRequest{
		Session: forgetPasswordRes.GetSession(),
		Code:    hGet.Code,
	}

	verificationRes, verificationResErr := authServiceClient.Verification(ctx, verificationParams)
	require.NoError(t, verificationResErr)

	resetPasswordParams := &authv1.ResetPasswordRequest{
		Session:         verificationRes.GetSession(),
		Password:        &passwordv1.Password{Value: newPassword},
		ConfirmPassword: &passwordv1.Password{Value: newPassword},
	}

	resetPasswordRes, resetPasswordResErr := authServiceClient.ResetPassword(ctx, resetPasswordParams)
	require.NoError(t, resetPasswordResErr)
	assert.NotNil(t, resetPasswordRes)

	loginParams := &authv1.LoginRequest{
		Email:    email,
		Password: &passwordv1.Password{Value: newPassword},
	}
	loginRes, loginResErr := authServiceClient.Login(ctx, loginParams)
	require.NoError(t, loginResErr)
	assert.NotNil(t, loginRes)
}
