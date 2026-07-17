package config

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"neupaneanish.com.np/authentication/internal/domain"
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
	Domain       string
	API          string
}

func LoadEnv(ctx context.Context) (*Env, error) {
	databaseURL, databaseURLErr := env.ValidateEnv("DATABASE_URL")
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

	url, urlErr := env.ValidateEnv("DOMAIN")
	if urlErr != nil {
		return nil, urlErr
	}

	domainVerification, domainVerificationErr := env.ValidateEnv("DOMAIN_VERIFICATION")
	if domainVerificationErr != nil {
		return nil, domainVerificationErr
	}

	domainName, domainNameErr := env.ValidateEnv("DOMAIN_NAME")
	if domainNameErr != nil {
		return nil, domainNameErr
	}

	validDomain, validDomainErr := domain.ValidateDomainWithTXT(ctx, strings.ToLower(url), domainVerification)
	if validDomainErr != nil {
		return nil, validDomainErr
	}

	api := fmt.Sprintf("%s.%s", strings.ToLower(domainName), validDomain)

	return &Env{
		DatabaseURL:  databaseURL,
		ValkeyURL:    valkeyURL,
		JWTKey:       jwtKey,
		TwoFactorKey: twoFactorKey,
		Issuer:       env.ValidateDefaultEnv("ISSUER", "Anish Neupane"),
		Port:         port,
		HTTPPort:     httpPort,
		ServiceName:  env.ValidateDefaultEnv("SERVICE_NAME", "neupaneanish.com.np/authentication"),
		Environment:  environment,
		TelemetryURL: telemetryURL,
		Domain:       validDomain,
		API:          api,
	}, nil
}
