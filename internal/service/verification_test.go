//go:build integration

package service_test

import (
	"crypto/rand"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"neupaneanish.com.np/authentication/internal/enum"

	"neupaneanish.com.np/authentication/internal/errs"
	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"
)

func TestVerification(t *testing.T) {
	t.Parallel()

	// Rate Limiter
	t.Run("Rate Limiter Session", func(t *testing.T) {
		t.Parallel()
		req := &externalAuthenticationv1.VerificationRequest{
			Session: rand.Text(),
			Code:    &externalAuthenticationv1.VerificationRequest_Email{Email: "12345678"},
		}

		for i := range 6 {
			res, err := externalAuthenticationServiceClient.Verification(t.Context(), req)
			require.Error(t, err)
			assert.Nil(t, res)
			if i < 5 {
				assert.Equal(t, errs.ErrSessionExpired, err)
			} else {
				assert.Equal(t, errs.ErrTooManyRequest, err)
			}
		}
	})

	t.Run("Rate Limiter Account", func(t *testing.T) {
		t.Parallel()
		verificationRateLimiter(t, uuid.NewV7().String(), enum.MethodLogin, enum.VerificationMethodAccount, false)
	})

	t.Run("Rate Limiter Email", func(t *testing.T) {
		t.Parallel()
		verificationRateLimiter(t, uuid.NewV7().String(), enum.MethodLogin, enum.VerificationMethodEmail, false)
	})

	t.Run("Rate Limiter Reset", func(t *testing.T) {
		t.Parallel()
		verificationRateLimiter(
			t,
			uuid.NewV7().String(),
			enum.MethodForgetPassword,
			enum.VerificationMethodReset,
			false,
		)
	})

	t.Run("Rate Limiter Two Factor TOTP", func(t *testing.T) {
		t.Parallel()
		verificationRateLimiterTwoFactor(t, false)
	})

	t.Run("Rate Limiter Two Factor Recovery", func(t *testing.T) {
		t.Parallel()
		verificationRateLimiterTwoFactor(t, true)
	})

	// Invalid Method
	t.Run("Invalid Method", func(t *testing.T) {
		t.Parallel()

		session, code := seedVerificationSession(t, uuid.NewV7().String(), "Test", enum.VerificationMethodEmail, false)
		req := &externalAuthenticationv1.VerificationRequest{
			Session: session,
			Code:    &externalAuthenticationv1.VerificationRequest_Email{Email: strings.ReplaceAll(code, "-", "")},
		}
		res, err := externalAuthenticationServiceClient.Verification(t.Context(), req)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrSessionExpired, err)
	})

	t.Run("Invalid Verification Method", func(t *testing.T) {
		t.Parallel()

		session, code := seedVerificationSession(t, uuid.NewV7().String(), enum.MethodForgetPassword, "test", false)
		req := &externalAuthenticationv1.VerificationRequest{
			Session: session,
			Code:    &externalAuthenticationv1.VerificationRequest_Email{Email: strings.ReplaceAll(code, "-", "")},
		}
		res, err := externalAuthenticationServiceClient.Verification(t.Context(), req)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrSessionExpired, err)
	})

	// Register
	t.Run("Register Method No User", func(t *testing.T) {
		t.Parallel()
		verificationNoUser(t, enum.MethodRegister, enum.VerificationMethodAccount)
	})

	t.Run("Register Method Account Success", func(t *testing.T) {
		t.Parallel()

		res := successVerification(
			t,
			enum.MethodRegister,
			enum.VerificationMethodAccount,
			enum.UserStatusPending,
		)
		assert.NotEmpty(t, res.GetToken().GetAccess())
	})

	t.Run("Register Method Account Email Invalid", func(t *testing.T) {
		t.Parallel()

		session, code := seedVerificationSession(
			t,
			uuid.NewV7().String(),
			enum.MethodRegister,
			enum.VerificationMethodEmail,
			false,
		)

		req := &externalAuthenticationv1.VerificationRequest{
			Session: session,
			Code:    &externalAuthenticationv1.VerificationRequest_Email{Email: strings.ReplaceAll(code, "-", "")},
		}
		res, err := externalAuthenticationServiceClient.Verification(t.Context(), req)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrSessionExpired, err)
	})

	// Login
	t.Run("Login Method No User Account", func(t *testing.T) {
		t.Parallel()
		verificationNoUser(t, enum.MethodLogin, enum.VerificationMethodAccount)
	})

	t.Run("Login Method No User Email", func(t *testing.T) {
		t.Parallel()
		verificationNoUser(t, enum.MethodLogin, enum.VerificationMethodEmail)
	})

	t.Run("Login Method Account Two Factor Invalid Verification Method", func(t *testing.T) {
		t.Parallel()
		session, code := seedVerificationSession(
			t,
			uuid.NewV7().String(),
			enum.MethodLogin,
			enum.VerificationMethodTwoFactor,
			false,
		)
		req := &externalAuthenticationv1.VerificationRequest{
			Session: session,
			Code:    &externalAuthenticationv1.VerificationRequest_Email{Email: strings.ReplaceAll(code, "-", "")},
		}
		res, err := externalAuthenticationServiceClient.Verification(t.Context(), req)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrSessionExpired, err)
	})

	t.Run("Login Method Account Code Invalid", func(t *testing.T) {
		t.Parallel()

		session, _ := seedVerificationSession(
			t,
			uuid.NewV7().String(),
			enum.MethodLogin,
			enum.VerificationMethodAccount,
			true,
		)

		req := &externalAuthenticationv1.VerificationRequest{
			Session: session,
			Code:    &externalAuthenticationv1.VerificationRequest_Email{Email: "12345678"},
		}
		res, err := externalAuthenticationServiceClient.Verification(t.Context(), req)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrInvalidCode, err)
	})

	t.Run("Login Method Account Two Factor Success", func(t *testing.T) {
		t.Parallel()

		session, code := seedVerificationSession(
			t,
			uuid.NewV7().String(),
			enum.MethodLogin,
			enum.VerificationMethodAccount,
			true,
		)

		req := &externalAuthenticationv1.VerificationRequest{
			Session: session,
			Code:    &externalAuthenticationv1.VerificationRequest_Email{Email: strings.ReplaceAll(code, "-", "")},
		}
		res, err := externalAuthenticationServiceClient.Verification(t.Context(), req)
		require.NoError(t, err)
		assert.NotNil(t, res)
		assert.NotEmpty(t, res.GetVerification().GetSession())
	})

	t.Run("Login Method Account Success", func(t *testing.T) {
		t.Parallel()

		res := successVerification(t, enum.MethodLogin, enum.VerificationMethodAccount, enum.UserStatusPending)
		assert.NotEmpty(t, res.GetToken().GetAccess())
	})

	t.Run("Login Method Email Success", func(t *testing.T) {
		t.Parallel()

		res := successVerification(t, enum.MethodLogin, enum.VerificationMethodEmail, enum.UserStatusActive)
		assert.NotEmpty(t, res.GetToken().GetAccess())
	})

	t.Run("Login Method, Two Factor TOTP Success", func(t *testing.T) {
		t.Parallel()

		userID, secret, _ := seedTwoFactor(t, false)
		code, codeErr := totp.GenerateCode(secret, time.Now())
		require.NoError(t, codeErr)
		session, _ := seedVerificationSession(t, userID, enum.MethodLogin, enum.VerificationMethodTwoFactor, false)
		req := &externalAuthenticationv1.VerificationRequest{
			Session: session,
			Code:    &externalAuthenticationv1.VerificationRequest_Totp{Totp: code},
		}
		res, err := externalAuthenticationServiceClient.Verification(t.Context(), req)
		require.NoError(t, err)
		assert.NotNil(t, res)
		assert.NotEmpty(t, res.GetToken().GetAccess())
	})

	t.Run("Login Method, Two Factor Recovery Success", func(t *testing.T) {
		t.Parallel()

		userID, _, recoveryCodes := seedTwoFactor(t, true)
		session, _ := seedVerificationSession(t, userID, enum.MethodLogin, enum.VerificationMethodTwoFactor, false)
		req := &externalAuthenticationv1.VerificationRequest{
			Session: session,
			Code: &externalAuthenticationv1.VerificationRequest_Recovery{
				Recovery: strings.ReplaceAll(recoveryCodes[0], "-", ""),
			},
		}
		res, err := externalAuthenticationServiceClient.Verification(t.Context(), req)
		require.NoError(t, err)
		assert.NotNil(t, res)
		assert.NotEmpty(t, res.GetToken().GetAccess())
	})

	// Forget
	t.Run("Forget Password Method No User Account", func(t *testing.T) {
		t.Parallel()
		verificationNoUser(t, enum.MethodForgetPassword, enum.VerificationMethodAccount)
	})

	t.Run("Forget Password Method No User Email", func(t *testing.T) {
		t.Parallel()
		verificationNoUser(t, enum.MethodForgetPassword, enum.VerificationMethodEmail)
	})

	t.Run("Forget Password Method Two Factor Error", func(t *testing.T) {
		t.Parallel()

		session, code := seedVerificationSession(
			t,
			uuid.NewV7().String(),
			enum.MethodForgetPassword,
			enum.VerificationMethodTwoFactor,
			true,
		)

		req := &externalAuthenticationv1.VerificationRequest{
			Session: session,
			Code:    &externalAuthenticationv1.VerificationRequest_Email{Email: strings.ReplaceAll(code, "-", "")},
		}
		res, err := externalAuthenticationServiceClient.Verification(t.Context(), req)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, errs.ErrSessionExpired, err)
	})

	t.Run("Forget Password Invalid Code Type", func(t *testing.T) {
		t.Parallel()
		verificationInvalidCodeType(t, enum.MethodForgetPassword, enum.VerificationMethodAccount)
	})

	t.Run("Forget Password Method Account Success", func(t *testing.T) {
		t.Parallel()

		res := successVerification(t, enum.MethodForgetPassword, enum.VerificationMethodEmail, enum.UserStatusPending)
		assert.NotEmpty(t, res.GetVerification().GetSession())
	})

	t.Run("Forget Password Method Email Success", func(t *testing.T) {
		t.Parallel()

		res := successVerification(t, enum.MethodForgetPassword, enum.VerificationMethodEmail, enum.UserStatusActive)
		assert.NotEmpty(t, res.GetVerification().GetSession())
	})
}

func verificationRateLimiter(
	t *testing.T,
	userID string,
	method enum.Method,
	verificationMethod enum.VerificationMethod,
	enabledTwoFactor bool,
) {
	t.Helper()

	session, _ := seedVerificationSession(t, userID, method, verificationMethod, enabledTwoFactor)

	for i := range 6 {
		req := &externalAuthenticationv1.VerificationRequest{}

		switch verificationMethod {
		case enum.VerificationMethodEmail, enum.VerificationMethodAccount, enum.VerificationMethodReset:
			req = &externalAuthenticationv1.VerificationRequest{
				Session: session,
				Code:    &externalAuthenticationv1.VerificationRequest_Email{Email: "12345678"},
			}

		case enum.VerificationMethodTwoFactor:
			req = &externalAuthenticationv1.VerificationRequest{
				Session: session,
				Code:    &externalAuthenticationv1.VerificationRequest_Totp{Totp: "123456"},
			}
		}

		res, err := externalAuthenticationServiceClient.Verification(t.Context(), req)
		require.Error(t, err)
		assert.Nil(t, res)
		if i < 5 {
			assert.Equal(t, errs.ErrInvalidCode, err)
		} else {
			assert.Equal(t, errs.ErrTooManyRequest, err)
		}
	}
}

func verificationRateLimiterTwoFactor(t *testing.T, recovery bool) {
	userID, _, _ := seedTwoFactor(t, recovery)
	session, _ := seedVerificationSession(t, userID, enum.MethodLogin, enum.VerificationMethodTwoFactor, false)

	req := &externalAuthenticationv1.VerificationRequest{}

	if recovery {
		req = &externalAuthenticationv1.VerificationRequest{
			Session: session,
			Code:    &externalAuthenticationv1.VerificationRequest_Recovery{Recovery: "1234567890"},
		}
	} else {
		req = &externalAuthenticationv1.VerificationRequest{
			Session: session,
			Code:    &externalAuthenticationv1.VerificationRequest_Totp{Totp: "123456"},
		}
	}

	for i := range 6 {
		res, err := externalAuthenticationServiceClient.Verification(t.Context(), req)
		require.Error(t, err)
		assert.Nil(t, res)
		if i < 5 {
			assert.Equal(t, errs.ErrInvalidCode, err)
		} else {
			assert.Equal(t, errs.ErrTooManyRequest, err)
		}
	}
}

func successVerification(
	t *testing.T,
	method enum.Method,
	verificationMethod enum.VerificationMethod,
	status enum.UserStatus,
) *externalAuthenticationv1.VerificationResponse {
	t.Helper()

	userID, userIDErr := seedUser(
		t.Context(),
		cfg.Domain.GenerateEmail(uuid.NewV7().String()),
		"Password@12345",
		status,
		false,
	)
	require.NoError(t, userIDErr)

	session, code := seedVerificationSession(
		t,
		userID,
		method,
		verificationMethod,
		false,
	)
	req := &externalAuthenticationv1.VerificationRequest{
		Session: session,
		Code:    &externalAuthenticationv1.VerificationRequest_Email{Email: strings.ReplaceAll(code, "-", "")},
	}
	res, err := externalAuthenticationServiceClient.Verification(t.Context(), req)
	require.NoError(t, err)
	assert.NotNil(t, res)

	return res
}

func verificationNoUser(t *testing.T, method enum.Method, verificationMethod enum.VerificationMethod) {
	t.Helper()

	session, code := seedVerificationSession(
		t,
		uuid.NewV7().String(),
		method,
		verificationMethod,
		false,
	)
	req := &externalAuthenticationv1.VerificationRequest{
		Session: session,
		Code: &externalAuthenticationv1.VerificationRequest_Email{
			Email: strings.ReplaceAll(code, "-", ""),
		},
	}
	res, err := externalAuthenticationServiceClient.Verification(t.Context(), req)
	require.Error(t, err)
	assert.Nil(t, res)
	assert.Equal(t, errs.ErrSessionExpired, err)
}

func verificationInvalidCodeType(
	t *testing.T,
	method enum.Method,
	verificationMethod enum.VerificationMethod,
) {
	t.Helper()

	session, _ := seedVerificationSession(
		t,
		uuid.NewV7().String(),
		method,
		verificationMethod,
		false,
	)
	req := &externalAuthenticationv1.VerificationRequest{
		Session: session,
		Code:    &externalAuthenticationv1.VerificationRequest_Totp{Totp: "123456"},
	}
	res, err := externalAuthenticationServiceClient.Verification(t.Context(), req)
	require.Error(t, err)
	assert.Nil(t, res)
	assert.Equal(t, errs.ErrSessionExpired, err)
}
