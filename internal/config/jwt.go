package config

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"

	"neupaneanish.com.np/authentication/internal/errs"
	"neupaneanish.com.np/authentication/internal/utils"
)

type JWT struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
	issuer  string
	logger  *slog.Logger
	storage *jwkset.MemoryJWKSet
	kid     string
}

type GenerateJwt struct {
	Access   string
	Refresh  string
	ExpiryAt time.Time
}

func NewJWT(ctx context.Context, key string, issuer string, logger *slog.Logger) (*JWT, error) {
	private, public, err := validateKey(key)
	if err != nil {
		return nil, err
	}

	storage := jwkset.NewMemoryStorage()

	kid := hex.EncodeToString(public)
	metadata := jwkset.JWKMetadataOptions{
		ALG: jwkset.AlgEdDSA,
		KID: kid,
		USE: jwkset.UseSig,
	}

	jwkOptions := jwkset.JWKOptions{
		Metadata: metadata,
	}

	jwk, jwkErr := jwkset.NewJWKFromKey(public, jwkOptions)
	if jwkErr != nil {
		return nil, jwkErr
	}

	if writeErr := storage.KeyWrite(ctx, jwk); writeErr != nil {
		return nil, writeErr
	}

	return &JWT{
		private: private,
		public:  public,
		issuer:  issuer,
		logger:  logger,
		storage: storage,
		kid:     kid,
	}, nil
}

func (j *JWT) GenerateToken(
	userID string,
	id string,
) (*GenerateJwt, error) {
	now := time.Now().UTC()
	expiryAt := now.Add(utils.AccessSessionExpiry)

	claims := jwt.RegisteredClaims{
		Issuer:    j.issuer,
		Subject:   userID,
		ExpiresAt: jwt.NewNumericDate(expiryAt),
		NotBefore: jwt.NewNumericDate(now),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        id,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = j.kid

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

func (j *JWT) Jwks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=86400")

	jwks, err := j.storage.JSONPublic(r.Context())
	if err != nil {
		j.logger.ErrorContext(r.Context(), "JWKS generation failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if _, err = w.Write(jwks); err != nil {
		j.logger.ErrorContext(r.Context(), "JWKS response failed", "error", err)
	}
}
