package config

import (
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

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
	expiryAt := now.Add(accessExpiry)

	claims := JwtClaims{
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
