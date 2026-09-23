package config

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	development = "development"
	production  = "production"

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

func validateEnv(key string) (string, error) {
	env := os.Getenv(key)
	value := strings.TrimSpace(env)
	if value == "" {
		return "", fmt.Errorf("%s is missing", key)
	}
	return value, nil
}

func validateDefaultEnv(key string, def string) string {
	env := os.Getenv(key)
	value := strings.TrimSpace(env)
	if value == "" {
		return def
	}
	return value
}

func validatePort(key, def string) (string, error) {
	port := validateDefaultEnv(key, def)
	value, valueErr := strconv.Atoi(port)
	if valueErr != nil || value < 80 || value > 65535 {
		return "", fmt.Errorf("%s must be between 80  and 65535", key)
	}
	return port, nil
}

func validateBoolEnv(key string, def bool) bool {
	env := os.Getenv(key)
	value := strings.TrimSpace(env)
	if value == "" {
		return def
	}
	val, err := strconv.ParseBool(value)
	if err != nil {
		return def
	}
	return val
}

func databaseURL() (string, error) {
	databaseHost, databaseHostErr := validateEnv("DATABASE_HOST")
	if databaseHostErr != nil {
		return "", databaseHostErr
	}

	databaseName, databaseErr := validateEnv("DATABASE_NAME")
	if databaseErr != nil {
		return "", databaseErr
	}

	databaseUser, databaseUsernameErr := validateEnv("DATABASE_USER")
	if databaseUsernameErr != nil {
		return "", databaseUsernameErr
	}

	databasePassword, databasePasswordErr := validateEnv("DATABASE_PASSWORD")
	if databasePasswordErr != nil {
		return "", databasePasswordErr
	}

	databasePort, databasePortErr := validatePort("DATABASE_PORT", "5432")
	if databasePortErr != nil {
		return "", databasePortErr
	}

	databaseSSL := validateBoolEnv("DATABASE_SSL", true)
	sslMode := "require"
	if !databaseSSL {
		sslMode = "disable"
	}

	hostPort := net.JoinHostPort(databaseHost, databasePort)

	dbURL := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(databaseUser, databasePassword),
		Host:     hostPort,
		Path:     databaseName,
		RawQuery: "sslmode=" + sslMode,
	}

	return dbURL.String(), nil
}
