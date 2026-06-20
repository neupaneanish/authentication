//go:build e2e

package service_test

import (
	"crypto/rand"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authv1 "neupaneanish.com.np/api/internal/protobuf/auth/v1"
	passwordv1 "neupaneanish.com.np/api/internal/protobuf/common/password/v1"
	"neupaneanish.com.np/api/internal/redis"
	"neupaneanish.com.np/api/internal/utils"
)

func TestRegisterToLoginE2E(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	id := atomic.AddUint64(&phoneCounter, 1)

	rawPassword := "Password@1234"
	email := cfg.Domain.GenerateEmail(rand.Text())
	phone := fmt.Sprintf("+1562%07d", 5000000+id)

	req := &authv1.RegisterRequest{
		Email:           email,
		Password:        &passwordv1.Password{Value: rawPassword},
		ConfirmPassword: &passwordv1.Password{Value: rawPassword},
		Phone:           phone,
	}

	response, err := authServiceClient.Register(ctx, req)
	require.NoError(t, err)
	assert.NotNil(t, response)

	accountSession, accountSessionErr := redis.HGet[utils.AccountVerificationSession](
		ctx,
		utils.AccountVerificationSessionPrefix,
		response.GetSession(),
		cfg.Client,
	)
	require.NoError(t, accountSessionErr)
	assert.NotNil(t, accountSession)

	verificationReq := &authv1.AccountVerificationRequest{
		Session: response.GetSession(),
		Code:    accountSession.Code,
	}

	verificationResponse, verificationResponseErr := authServiceClient.AccountVerification(ctx, verificationReq)
	require.NoError(t, verificationResponseErr)
	assert.NotNil(t, verificationResponse.GetToken())
	assert.NotEmpty(t, verificationResponse.GetToken().GetAccess())
}
