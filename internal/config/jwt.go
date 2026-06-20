package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"neupaneanish.com.np/authentication/internal/errs"
)

type JWT struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
	issuer  string
	logger  *slog.Logger
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

const accessSessionExpiry = 15 * time.Minute

func NewJWT(key string, issuer string, logger *slog.Logger) (*JWT, error) {
	_, private, public, err := validateKey(key)
	if err != nil {
		return nil, err
	}
	return &JWT{
		private: private,
		public:  public,
		issuer:  issuer,
		logger:  logger,
	}, nil
}

func (j *JWT) GenerateToken(
	userID string,
	role string,
	id string,
) (*GenerateJwt, error) {
	now := time.Now().UTC()
	expiryAt := now.Add(accessSessionExpiry)

	claims := &JwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    j.issuer,
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(expiryAt),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        id,
		},
		Role: role,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)

	access, err := token.SignedString(j.private)
	if err != nil {
		j.logger.Error("Token Signed", "error", err)
		return nil, errs.ErrInternalServer
	}

	refresh := rand.Text()

	return &GenerateJwt{
		Access:   access,
		Refresh:  refresh,
		ExpiryAt: expiryAt,
	}, nil
}

func (j *JWT) ValidateToken(access string) (*JwtClaims, error) {
	token, err := jwt.ParseWithClaims(access, &JwtClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			j.logger.Error("unexpected signing method", "error", token.Header["alg"])
			return nil, jwt.ErrTokenUnverifiable
		}
		return j.public, nil
	})

	if err != nil {
		j.logger.Error("JWT Validation", "error", err)
		return nil, errs.ErrInvalidTokenOrExpired
	}

	claims, ok := token.Claims.(*JwtClaims)
	if !ok {
		j.logger.Error("JWT Invalid claims", "claims", claims)
		return nil, errs.ErrInvalidTokenOrExpired
	}
	return claims, nil
}
