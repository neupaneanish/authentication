package config

import (
	"time"

	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeylimiter"
)

func NewLimiter(valkeyClient valkey.Client) (*Limiter, error) {
	login, loginErr := limiter(
		loginLimiterPrefix,
		limiterWindow,
		valkeyClient,
	)
	if loginErr != nil {
		return nil, loginErr
	}

	loginTwoFactor, loginTwoFactorErr := limiter(
		loginTwoFactorLimiterPrefix,
		limiterWindow,
		valkeyClient,
	)
	if loginTwoFactorErr != nil {
		return nil, loginTwoFactorErr
	}

	forgetPassword, forgetPasswordErr := limiter(
		fpLimiterPrefix,
		forgetPasswordLimiterWindow,
		valkeyClient,
	)
	if forgetPasswordErr != nil {
		return nil, forgetPasswordErr
	}

	verification, verificationErr := limiter(
		verificationLimiterPrefix,
		limiterWindow,
		valkeyClient,
	)
	if verificationErr != nil {
		return nil, verificationErr
	}

	resetPassword, resetPasswordErr := limiter(
		rpLimiterPrefix,
		limiterWindow,
		valkeyClient,
	)
	if resetPasswordErr != nil {
		return nil, resetPasswordErr
	}

	return &Limiter{
		Login:          login,
		LoginTwoFactor: loginTwoFactor,
		ForgetPassword: forgetPassword,
		Verification:   verification,
		ResetPassword:  resetPassword,
	}, nil
}

func limiter(
	prefix string,
	window time.Duration,
	client valkey.Client,
) (valkeylimiter.RateLimiterClient, error) {
	lim, err := valkeylimiter.NewRateLimiter(valkeylimiter.RateLimiterOption{
		KeyPrefix: prefix,
		ClientBuilder: func(_ valkey.ClientOption) (valkey.Client, error) {
			return client, nil
		},
		Limit:  limiterLimit,
		Window: window,
	})

	if err != nil {
		return nil, err
	}
	return lim, nil
}
