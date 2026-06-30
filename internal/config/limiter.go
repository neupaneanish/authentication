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
	Refresh                   valkeylimiter.RateLimiterClient
	RefreshUserID             valkeylimiter.RateLimiterClient
	PasswordWorkflow          valkeylimiter.RateLimiterClient
	TwoFactorWorkflow         valkeylimiter.RateLimiterClient
}

type limiterTask struct {
	target *valkeylimiter.RateLimiterClient
	prefix string
	limit  int
	window time.Duration
}

func NewRateLimiter(client valkey.Client) (*RateLimiter, error) {
	limiter := &RateLimiter{}

	tasks := []limiterTask{
		{&limiter.Login, loginLimiterSessionPrefix, limiterLimit, limiterWindowSession},
		{&limiter.LoginTwoFactor, loginTwoFactorSessionLimiterPrefix, limiterLimit, limiterWindowSession},
		{&limiter.ForgetPassword, fpLimiterPrefix, limiterLimit, limiterWindowSession},
		{&limiter.Verification, verificationSessionLimiterPrefix, limiterLimit, limiterWindowSession},
		{&limiter.ResetPassword, rpSessionLimiterPrefix, limiterLimit, limiterWindowSession},
		{&limiter.ResendVerification, resendVerificationSessionLimiterPrefix, limiterLimit, limiterWindowSession},
		{&limiter.AccountVerification, accountVerificationSessionLimiterPrefix, limiterLimit, limiterWindowSession},
		{&limiter.Refresh, refreshSessionLimiterPrefix, refreshSessionLimiterLimit, limiterRefreshWindowSession},

		{&limiter.LoginTwoFactorUserID, loginTwoFactorLimiterPrefix, limiterLimit, limiterWindowUserID},
		{&limiter.VerificationUserID, verificationLimiterPrefix, limiterLimit, limiterWindowUserID},
		{&limiter.ResetPasswordUserID, rpLimiterPrefix, limiterLimit, limiterWindowUserID},
		{&limiter.ResendVerificationUserID, resendVerificationLimiterPrefix, limiterLimit, limiterWindowUserID},
		{&limiter.AccountVerificationUserID, accountVerificationLimiterPrefix, limiterLimit, limiterWindowUserID},
		{&limiter.RefreshUserID, refreshLimiterPrefix, refreshUserIDLimiterLimit, limiterRefreshWindowUserID},
		{&limiter.PasswordWorkflow, passwordWorkflowLimiterPrefix, limiterLimit, limiterWindowUserID},
		{&limiter.TwoFactorWorkflow, twoFactorWorkflowLimiterPrefix, limiterLimit, limiterWindowUserID},
	}

	for _, task := range tasks {
		instance, err := Limiter(task.prefix, task.limit, task.window, client)
		if err != nil {
			return nil, err
		}
		*task.target = instance
	}

	return limiter, nil
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
