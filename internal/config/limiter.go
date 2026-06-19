package config

import (
	"time"

	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeylimiter"
)

type RateLimiter struct {
	Login                     valkeylimiter.RateLimiterClient
	LoginTwoFactor            valkeylimiter.RateLimiterClient
	LoginTwoFactorUserID      valkeylimiter.RateLimiterClient
	ForgetPassword            valkeylimiter.RateLimiterClient
	Verification              valkeylimiter.RateLimiterClient
	VerificationUserID        valkeylimiter.RateLimiterClient
	ResetPassword             valkeylimiter.RateLimiterClient
	ResetPasswordUserID       valkeylimiter.RateLimiterClient
	AccountVerification       valkeylimiter.RateLimiterClient
	AccountVerificationUserID valkeylimiter.RateLimiterClient
	ResendVerification        valkeylimiter.RateLimiterClient
	ResendVerificationUserID  valkeylimiter.RateLimiterClient
}

func NewRateLimiter(client valkey.Client) (*RateLimiter, error) {
	limiter := &RateLimiter{}

	if sessionErr := initSessionLimiter(limiter, client); sessionErr != nil {
		return nil, sessionErr
	}

	if userIDErr := initUserIDLimiter(limiter, client); userIDErr != nil {
		return nil, userIDErr
	}
	return limiter, nil
}

func initSessionLimiter(limiter *RateLimiter, client valkey.Client) error {
	login, loginErr := Limiter(
		loginLimiterSessionPrefix,
		limiterLimit,
		limiterWindowSession,
		client,
	)
	if loginErr != nil {
		return loginErr
	}

	loginTwoFactor, loginTwoFactorErr := Limiter(
		loginTwoFactorSessionLimiterPrefix,
		limiterLimit,
		limiterWindowSession,
		client,
	)
	if loginTwoFactorErr != nil {
		return loginTwoFactorErr
	}

	forgetPassword, forgetPasswordErr := Limiter(
		fpLimiterPrefix,
		limiterLimit,
		limiterWindowSession,
		client,
	)
	if forgetPasswordErr != nil {
		return forgetPasswordErr
	}

	verification, verificationErr := Limiter(
		verificationSessionLimiterPrefix,
		limiterLimit,
		limiterWindowSession,
		client,
	)
	if verificationErr != nil {
		return verificationErr
	}

	resetPassword, resetPasswordErr := Limiter(
		rpSessionLimiterPrefix,
		limiterLimit,
		limiterWindowSession,
		client,
	)
	if resetPasswordErr != nil {
		return resetPasswordErr
	}

	resendVerification, resendVerificationErr := Limiter(
		resendVerificationSessionLimiterPrefix,
		limiterLimit,
		limiterWindowSession,
		client,
	)
	if resendVerificationErr != nil {
		return resendVerificationErr
	}

	accountVerification, accountVerificationErr := Limiter(
		accountVerificationSessionLimiterPrefix,
		limiterLimit,
		limiterWindowSession,
		client,
	)
	if accountVerificationErr != nil {
		return accountVerificationErr
	}

	limiter.Login = login
	limiter.LoginTwoFactor = loginTwoFactor
	limiter.ForgetPassword = forgetPassword
	limiter.Verification = verification
	limiter.ResetPassword = resetPassword
	limiter.ResendVerification = resendVerification
	limiter.AccountVerification = accountVerification

	return nil
}

func initUserIDLimiter(limiter *RateLimiter, client valkey.Client) error {
	loginTwoFactorUserID, loginTwoFactorUserIDErr := Limiter(
		loginTwoFactorLimiterPrefix,
		limiterLimit,
		limiterWindowUserID,
		client,
	)
	if loginTwoFactorUserIDErr != nil {
		return loginTwoFactorUserIDErr
	}

	verificationUserID, verificationUserIDErr := Limiter(
		verificationLimiterPrefix,
		limiterLimit,
		limiterWindowUserID,
		client,
	)
	if verificationUserIDErr != nil {
		return verificationUserIDErr
	}

	resetPasswordUserID, resetPasswordUserIDErr := Limiter(
		rpLimiterPrefix,
		limiterLimit,
		limiterWindowUserID,
		client,
	)
	if resetPasswordUserIDErr != nil {
		return resetPasswordUserIDErr
	}

	resendVerificationUserID, resendVerificationUserIDErr := Limiter(
		resendVerificationLimiterPrefix,
		limiterLimit,
		limiterWindowUserID,
		client,
	)
	if resendVerificationUserIDErr != nil {
		return resendVerificationUserIDErr
	}

	accountVerificationUserID, accountVerificationUserIDErr := Limiter(
		accountVerificationLimiterPrefix,
		limiterLimit,
		limiterWindowUserID,
		client,
	)
	if accountVerificationUserIDErr != nil {
		return accountVerificationUserIDErr
	}

	limiter.LoginTwoFactorUserID = loginTwoFactorUserID
	limiter.VerificationUserID = verificationUserID
	limiter.ResetPasswordUserID = resetPasswordUserID
	limiter.ResendVerificationUserID = resendVerificationUserID
	limiter.AccountVerificationUserID = accountVerificationUserID

	return nil
}

func Limiter(
	prefix string,
	limit int,
	window time.Duration,
	client valkey.Client,
) (valkeylimiter.RateLimiterClient, error) {
	rateLimiter, err := valkeylimiter.NewRateLimiter(valkeylimiter.RateLimiterOption{
		KeyPrefix: prefix,
		ClientBuilder: func(_ valkey.ClientOption) (valkey.Client, error) {
			return client, nil
		},
		Limit:  limit,
		Window: window,
	})

	if err != nil {
		return nil, err
	}
	return rateLimiter, nil
}
