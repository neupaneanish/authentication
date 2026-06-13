package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

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

const accessSessionExpiry = 15 * time.Minute

func NewJWT(key string, issuer string) (*JWT, error) {
	_, private, public, err := validateKey(key)
	if err != nil {
		return nil, err
	}
	return &JWT{
		private: private,
		public:  public,
		issuer:  issuer,
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
		return nil, err
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
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.public, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*JwtClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid token")
}
