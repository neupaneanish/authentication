package config

import (
	"time"

	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeylimiter"
)

type RateLimiter struct {
	Login          valkeylimiter.RateLimiterClient
	ForgetPassword valkeylimiter.RateLimiterClient

	Verification          valkeylimiter.RateLimiterClient
	VerificationAccount   valkeylimiter.RateLimiterClient
	VerificationEmail     valkeylimiter.RateLimiterClient
	VerificationReset     valkeylimiter.RateLimiterClient
	VerificationTwoFactor valkeylimiter.RateLimiterClient

	ResetPassword       valkeylimiter.RateLimiterClient
	ResetPasswordUserID valkeylimiter.RateLimiterClient

	ResendVerification       valkeylimiter.RateLimiterClient
	ResendVerificationUserID valkeylimiter.RateLimiterClient

	ResendPasswordVerification       valkeylimiter.RateLimiterClient
	ResendPasswordVerificationUserID valkeylimiter.RateLimiterClient

	Refresh       valkeylimiter.RateLimiterClient
	RefreshUserID valkeylimiter.RateLimiterClient

	PasswordWorkflow  valkeylimiter.RateLimiterClient
	TwoFactorWorkflow valkeylimiter.RateLimiterClient
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
		{&limiter.ForgetPassword, fpLimiterSessionPrefix, limiterLimit, limiterWindowSession},

		{&limiter.Verification, verificationSessionLimiterPrefix, limiterLimit, limiterWindowSession},
		{&limiter.VerificationAccount, verificationAccountUserIDLimiterPrefix, limiterLimit, limiterWindowUserID},
		{&limiter.VerificationEmail, verificationEmailUserIDLimiterPrefix, limiterLimit, limiterWindowUserID},
		{&limiter.VerificationReset, verificationResetUserIDLimiterPrefix, limiterLimit, limiterWindowUserID},
		{&limiter.VerificationTwoFactor, verificationTwoFactorUserIDLimiterPrefix, limiterLimit, limiterWindowUserID},

		{&limiter.ResetPassword, rpSessionLimiterPrefix, limiterLimit, limiterWindowSession},
		{&limiter.ResetPasswordUserID, rpUserIDLimiterPrefix, limiterLimit, limiterWindowUserID},

		{&limiter.ResendVerification, resendVerificationSessionLimiterPrefix, limiterLimit, limiterWindowSession},
		{&limiter.ResendVerificationUserID, resendVerificationUserIDLimiterPrefix, limiterLimit, limiterWindowUserID},

		{
			&limiter.ResendPasswordVerification,
			resendAccountVerificationSessionLimiterPrefix,
			limiterLimit,
			limiterWindowSession,
		},
		{
			&limiter.ResendPasswordVerificationUserID,
			resendAccountVerificationUserIDLimiterPrefix,
			limiterLimit,
			limiterWindowUserID,
		},

		{&limiter.Refresh, refreshSessionLimiterPrefix, refreshSessionLimiterLimit, limiterRefreshWindowSession},
		{&limiter.RefreshUserID, refreshLimiterUserIDPrefix, refreshUserIDLimiterLimit, limiterRefreshWindowUserID},

		{&limiter.PasswordWorkflow, passwordWorkflowLimiterPrefix, authenticationLimiterLimit, limiterWindowUserID},
		{&limiter.TwoFactorWorkflow, twoFactorWorkflowLimiterPrefix, authenticationLimiterLimit, limiterWindowUserID},
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
