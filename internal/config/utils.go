package config

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v5"
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
	accessExpiry          = 15 * time.Minute
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
	Jwt         *JWT
}

type JWT struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
	issuer  string
}

type GenerateJwt struct {
	Access   string
	Refresh  string
	ExpiryAt time.Time
}

type JwtClaims struct {
	jwt.RegisteredClaims

	Role string
}

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
