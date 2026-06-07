package config

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeylimiter"
	"neupaneanish.com.np/api/internal/repository"
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

	imageSize         = 250
	period            = 30
	recoveryCodeCount = 10
	recoveryCodeBytes = 5

	loginLimiterPrefix          = "limiter:login"
	loginTwoFactorLimiterPrefix = "limiter:login:two:factor"
	fpLimiterPrefix             = "limiter:forget:password"
	verificationLimiterPrefix   = "limiter:verification"
	rpLimiterPrefix             = "limiter:reset:password"

	limiterLimit  = 5
	limiterWindow = 5 * time.Minute

	forgetPasswordLimiterWindow = 10 * time.Minute
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
	SaaSDomain   string
}

type Config struct {
	Pool        *pgxpool.Pool
	Client      valkey.Client
	Logger      *slog.Logger
	Port        string
	Environment string
	ServiceName string
	Jwt         *JWT
	TwoFactor   *TwoFactor
	RateLimiter *Limiter
	Repository  *repository.Queries
	SaaSDomain  string
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

type TwoFactor struct {
	key    []byte
	issuer string
}

type GenerateTwoFactor struct {
	Secret string
	Image  []byte
	URL    string
}

type RecoveryCodes struct {
	Plain []string
	Hash  [][]byte
}

type Limiter struct {
	Login          valkeylimiter.RateLimiterClient
	LoginTwoFactor valkeylimiter.RateLimiterClient
	ForgetPassword valkeylimiter.RateLimiterClient
	Verification   valkeylimiter.RateLimiterClient
	ResetPassword  valkeylimiter.RateLimiterClient
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
