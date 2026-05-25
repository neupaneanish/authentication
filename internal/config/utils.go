package config

import (
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	envDevelopment = "development"
	envProduction  = "production"
)

const (
	databaseMinConnection = 5
	databaseMaxConnection = 25
	databaseConnLifeTime  = 30 * time.Minute
	databaseConnIdle      = 1 * time.Minute
	databasePingTimeout   = 5 * time.Second
)

type Env struct {
	DatabaseURL  string
	ValkeyURL    string
	JWTKey       string
	TwoFactorKey string
	Issuer       string
	Port         string
	ServiceName  string
	Environment  string
	TelemetryURL string
}

type Config struct {
	Pool        *pgxpool.Pool
	Logger      *slog.Logger
	Port        string
	Environment string
	ServiceName string
}
