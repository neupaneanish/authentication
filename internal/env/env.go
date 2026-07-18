package env

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

const (
	Development = "development"
	Production  = "production"
)

func ValidateEnv(key string) (string, error) {
	env := os.Getenv(key)
	value := strings.TrimSpace(env)
	if value == "" {
		return "", fmt.Errorf("%s is missing", key)
	}
	return value, nil
}

func ValidateDefaultEnv(key string, def string) string {
	env := os.Getenv(key)
	value := strings.TrimSpace(env)
	if value == "" {
		return def
	}
	return value
}

func ValidatePort(key, def string) (string, error) {
	port := ValidateDefaultEnv(key, def)
	value, valueErr := strconv.Atoi(port)
	if valueErr != nil || value < 80 || value > 65535 {
		return "", fmt.Errorf("%s must be between 80  and 65535", key)
	}
	return port, nil
}

func ValidateBoolEnv(key string, def bool) bool {
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

func DatabaseURL() (string, error) {
	databaseHost, databaseHostErr := ValidateEnv("DATABASE_HOST")
	if databaseHostErr != nil {
		return "", databaseHostErr
	}

	databaseName, databaseErr := ValidateEnv("DATABASE_NAME")
	if databaseErr != nil {
		return "", databaseErr
	}

	databaseUser, databaseUsernameErr := ValidateEnv("DATABASE_USER")
	if databaseUsernameErr != nil {
		return "", databaseUsernameErr
	}

	databasePassword, databasePasswordErr := ValidateEnv("DATABASE_PASSWORD")
	if databasePasswordErr != nil {
		return "", databasePasswordErr
	}

	databasePort, databasePortErr := ValidatePort("DATABASE_PORT", "5432")
	if databasePortErr != nil {
		return "", databasePortErr
	}

	databaseSSL := ValidateBoolEnv("DATABASE_SSL", true)
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
