package config

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"time"
)

const (
	loginLimiterSessionPrefix = "limiter:login:session"
	fpLimiterSessionPrefix    = "limiter:forget:password:session"

	verificationSessionLimiterPrefix         = "limiter:verification:session"
	verificationAccountUserIDLimiterPrefix   = "limiter:verification:account:userid"
	verificationEmailUserIDLimiterPrefix     = "limiter:verification:email:userid"
	verificationResetUserIDLimiterPrefix     = "limiter:verification:reset:userid"
	verificationTwoFactorUserIDLimiterPrefix = "limiter:verification:two:factor:userid"

	rpUserIDLimiterPrefix  = "limiter:reset:password:userid"
	rpSessionLimiterPrefix = "limiter:reset:password:session"

	resendVerificationUserIDLimiterPrefix  = "limiter:resend:verification:userid"
	resendVerificationSessionLimiterPrefix = "limiter:resend:verification:session"

	resendAccountVerificationUserIDLimiterPrefix  = "limiter:resend:password:verification:userid"
	resendAccountVerificationSessionLimiterPrefix = "limiter:resend:password:verification:session"

	refreshSessionLimiterPrefix = "limiter:refresh:session"
	refreshLimiterUserIDPrefix  = "limiter:refresh:userid"

	passwordWorkflowLimiterPrefix  = "limiter:password:workflow"
	twoFactorWorkflowLimiterPrefix = "limiter:two:factor:workflow"

	limiterLimit                = 5
	authenticationLimiterLimit  = 6
	refreshSessionLimiterLimit  = 2
	refreshUserIDLimiterLimit   = 4
	limiterRefreshWindowSession = 15 * time.Minute
	limiterRefreshWindowUserID  = 30 * time.Minute
	limiterWindowSession        = 5 * time.Minute
	limiterWindowUserID         = time.Hour
)

func validateKey(key string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	decode, decodeErr := hex.DecodeString(key)
	if decodeErr != nil {
		return nil, nil, decodeErr
	}

	if len(decode) != ed25519.SeedSize {
		return nil, nil, errors.New("invalid key")
	}

	privateKey := ed25519.NewKeyFromSeed(decode)
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, nil, errors.New("invalid Key")
	}

	return privateKey, publicKey, nil
}
