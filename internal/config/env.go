package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"neupaneanish.com.np/api/internal/utils"
)

func LoadEnv(ctx context.Context) (*Env, error) {
	databaseURL, databaseURLErr := validateEnv("DATABASE_URL")
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

	port := validateDefaultEnv("PORT", "50051")
	value, valueErr := strconv.Atoi(port)
	if valueErr != nil || value < 80 || value > 65535 {
		return nil, errors.New("PORT must be between 80  and 65535")
	}

	environment := validateDefaultEnv("ENVIRONMENT", "development")
	switch environment {
	case envDevelopment, envProduction:
	default:
		return nil, fmt.Errorf("ENVIRONMENT must be %s or %s", envDevelopment, envProduction)
	}

	telemetryURL, telemetryURLErr := validateEnv("TELEMETRY_URL")
	if telemetryURLErr != nil {
		return nil, telemetryURLErr
	}

	domain, domainErr := validateEnv("DOMAIN")
	if domainErr != nil {
		return nil, domainErr
	}

	domainVerification, domainVerificationErr := validateEnv("DOMAIN_VERIFICATION")
	if domainVerificationErr != nil {
		return nil, domainVerificationErr
	}

	domainName, domainNameErr := validateEnv("DOMAIN_NAME")
	if domainNameErr != nil {
		return nil, domainNameErr
	}

	validDomain, validDomainErr := utils.ValidateDomain(ctx, strings.ToLower(domain), domainVerification)
	if validDomainErr != nil {
		return nil, validDomainErr
	}

	api := fmt.Sprintf("%s.%s", strings.ToLower(domainName), validDomain)

	return &Env{
		DatabaseURL:  databaseURL,
		ValkeyURL:    valkeyURL,
		JWTKey:       jwtKey,
		TwoFactorKey: twoFactorKey,
		Issuer:       validateDefaultEnv("ISSUER", "Anish Neupane"),
		Port:         port,
		ServiceName:  validateDefaultEnv("SERVICE_NAME", api),
		Environment:  environment,
		TelemetryURL: telemetryURL,
		Domain:       api,
	}, nil
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
