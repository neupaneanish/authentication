package config

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"time"
)

const (
	loginLimiterSessionPrefix               = "limiter:login:session"
	loginTwoFactorLimiterPrefix             = "limiter:login:two:factor"
	loginTwoFactorSessionLimiterPrefix      = "limiter:login:two:factor:session"
	fpLimiterPrefix                         = "limiter:forget:password"
	verificationLimiterPrefix               = "limiter:verification"
	verificationSessionLimiterPrefix        = "limiter:verification:session"
	rpLimiterPrefix                         = "limiter:reset:password"
	rpSessionLimiterPrefix                  = "limiter:reset:password:session"
	resendVerificationLimiterPrefix         = "limiter:resend:verification"
	resendVerificationSessionLimiterPrefix  = "limiter:resend:verification:session"
	accountVerificationLimiterPrefix        = "limiter:account:verification"
	accountVerificationSessionLimiterPrefix = "limiter:account:verification:session"

	limiterLimit         = 5
	limiterWindowSession = 5 * time.Minute
	limiterWindowUserID  = time.Hour
)

func validateKey(key string) ([]byte, ed25519.PrivateKey, ed25519.PublicKey, error) {
	decode, decodeErr := hex.DecodeString(key)
	if decodeErr != nil {
		return nil, nil, nil, decodeErr
	}

	if len(decode) != ed25519.SeedSize {
		return nil, nil, nil, errors.New("invalid key")
	}

	privateKey := ed25519.NewKeyFromSeed(decode)
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, nil, nil, errors.New("invalid Key")
	}
	seed := privateKey.Seed()

	return seed, privateKey, publicKey, nil
}
