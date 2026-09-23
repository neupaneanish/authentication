package config

import (
	"errors"
	"fmt"
)

type Env struct {
	DatabaseURL   string
	ValkeyURL     string
	JWTKey        string
	TwoFactorKey  string
	Issuer        string
	Port          string
	HTTPPort      string
	ServiceName   string
	Environment   string
	TelemetryURL  string
	RedpandaURL   string
	RedpandaGroup string
	AllowFree     bool
	AllowRole     bool
}

func LoadEnv() (*Env, error) {
	dbURL, databaseURLErr := databaseURL()
	if databaseURLErr != nil {
		return nil, databaseURLErr
	}

	valkeyURL, valkeyURLErr := validateEnv("VALKEY_URL")
	if valkeyURLErr != nil {
		return nil, valkeyURLErr
	}

	jwtKey, jwtKeyErr := validateEnv("JWT_KEY")
	if jwtKeyErr != nil {
		return nil, jwtKeyErr
	}

	twoFactorKey, twoFactorKeyErr := validateEnv("TWO_FACTOR_KEY")
	if twoFactorKeyErr != nil {
		return nil, twoFactorKeyErr
	}

	port, portErr := validatePort("PORT", "50051")
	if portErr != nil {
		return nil, portErr
	}

	httpPort, httpPortErr := validatePort("HTTP_PORT", "8000")
	if httpPortErr != nil {
		return nil, httpPortErr
	}

	if port == httpPort {
		return nil, errors.New("GRPC and HTTP port cannot be same")
	}

	environment := validateDefaultEnv("ENVIRONMENT", development)
	switch environment {
	case development, production:
	default:
		return nil, fmt.Errorf("ENVIRONMENT must be %s or %s", development, production)
	}

	telemetryURL, telemetryURLErr := validateEnv("TELEMETRY_URL")
	if telemetryURLErr != nil {
		return nil, telemetryURLErr
	}

	redpandaURL, redpandaURLErr := validateEnv("REDPANDA_URL")
	if redpandaURLErr != nil {
		return nil, redpandaURLErr
	}

	return &Env{
		DatabaseURL:   dbURL,
		ValkeyURL:     valkeyURL,
		JWTKey:        jwtKey,
		TwoFactorKey:  twoFactorKey,
		Issuer:        validateDefaultEnv("ISSUER", "Founder"),
		Port:          port,
		HTTPPort:      httpPort,
		ServiceName:   validateDefaultEnv("SERVICE_NAME", "Founder Authentication"),
		Environment:   environment,
		TelemetryURL:  telemetryURL,
		AllowFree:     validateBoolEnv("ALLOW_FREE_EMAIL", false),
		AllowRole:     validateBoolEnv("ALLOW_ROLE_EMAIL", false),
		RedpandaURL:   redpandaURL,
		RedpandaGroup: validateDefaultEnv("REDPANDA_GROUP", "founder-authentication"),
	}, nil
}
