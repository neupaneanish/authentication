package config

import (
	"errors"
	"fmt"

	"neupaneanish.com.np/authentication/internal/env"
)

type Env struct {
	DatabaseURL  string
	ValkeyURL    string
	JWTKey       string
	TwoFactorKey string
	Issuer       string
	Port         string
	HTTPPort     string
	ServiceName  string
	Environment  string
	TelemetryURL string
	AllowFree    bool
	AllowRole    bool
}

func LoadEnv() (*Env, error) {
	databaseURL, databaseURLErr := env.DatabaseURL()
	if databaseURLErr != nil {
		return nil, databaseURLErr
	}

	valkeyURL, valkeyURLErr := env.ValidateEnv("VALKEY_URL")
	if valkeyURLErr != nil {
		return nil, valkeyURLErr
	}

	jwtKey, jwtKeyErr := env.ValidateEnv("JWT_KEY")
	if jwtKeyErr != nil {
		return nil, jwtKeyErr
	}

	twoFactorKey, twoFactorKeyErr := env.ValidateEnv("TWO_FACTOR_KEY")
	if twoFactorKeyErr != nil {
		return nil, twoFactorKeyErr
	}

	port, portErr := env.ValidatePort("PORT", "50051")
	if portErr != nil {
		return nil, portErr
	}

	httpPort, httpPortErr := env.ValidatePort("HTTP_PORT", "8000")
	if httpPortErr != nil {
		return nil, httpPortErr
	}

	if port == httpPort {
		return nil, errors.New("GRPC and HTTP port cannot be same")
	}

	environment := env.ValidateDefaultEnv("ENVIRONMENT", env.Development)
	switch environment {
	case env.Development, env.Production:
	default:
		return nil, fmt.Errorf("ENVIRONMENT must be %s or %s", env.Development, env.Production)
	}

	telemetryURL, telemetryURLErr := env.ValidateEnv("TELEMETRY_URL")
	if telemetryURLErr != nil {
		return nil, telemetryURLErr
	}

	return &Env{
		DatabaseURL:  databaseURL,
		ValkeyURL:    valkeyURL,
		JWTKey:       jwtKey,
		TwoFactorKey: twoFactorKey,
		Issuer:       env.ValidateDefaultEnv("ISSUER", "Founder"),
		Port:         port,
		HTTPPort:     httpPort,
		ServiceName:  env.ValidateDefaultEnv("SERVICE_NAME", "Founder Authentication"),
		Environment:  environment,
		TelemetryURL: telemetryURL,
		AllowFree:    env.ValidateBoolEnv("ALLOW_FREE_EMAIL", false),
		AllowRole:    env.ValidateBoolEnv("ALLOW_ROLE_EMAIL", false),
	}, nil
}
