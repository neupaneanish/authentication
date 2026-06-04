package config

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"image/png"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"neupaneanish.com.np/api/internal/repository"
)

func NewTwoFactor(
	key string,
	issuer string,
) (*TwoFactor, error) {
	masterKey, _, _, err := validateKey(key)
	if err != nil {
		return nil, err
	}

	return &TwoFactor{
		key:    masterKey,
		issuer: issuer,
	}, nil
}

func (f *TwoFactor) Generate(name string) (
	*GenerateTwoFactor,
	error,
) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      f.issuer,
		AccountName: name,
		Period:      period,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})

	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	img, imgErr := key.Image(imageSize, imageSize)
	if imgErr != nil {
		return nil, imgErr
	}

	if pngEncoderErr := png.Encode(&buf, img); pngEncoderErr != nil {
		return nil, pngEncoderErr
	}

	return &GenerateTwoFactor{
		Secret: key.Secret(),
		Image:  buf.Bytes(),
		URL:    key.URL(),
	}, nil
}

func (f *TwoFactor) Encrypt(raw string) ([]byte, error) {
	block, err := aes.NewCipher(f.key)
	if err != nil {
		return nil, err
	}

	gcm, gcmErr := cipher.NewGCM(block)
	if gcmErr != nil {
		return nil, gcmErr
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, nonceErr := rand.Read(nonce); nonceErr != nil {
		return nil, nonceErr
	}

	out := gcm.Seal(nonce, nonce, []byte(raw), nil)
	return out, nil
}

func (f *TwoFactor) decrypt(secret []byte) ([]byte, error) {
	block, blockErr := aes.NewCipher(f.key)
	if blockErr != nil {
		return nil, blockErr
	}

	gcm, gcmErr := cipher.NewGCM(block)
	if gcmErr != nil {
		return nil, gcmErr
	}

	nonceSize := gcm.NonceSize()
	if len(secret) < nonceSize {
		return nil, errors.New("invalid Secret")
	}

	nonce, realSecret := secret[:nonceSize], secret[nonceSize:]
	text, textErr := gcm.Open(nil, nonce, realSecret, nil)
	if textErr != nil {
		return nil, textErr
	}

	return text, nil
}

func (f *TwoFactor) Validate(
	code string,
	secret []byte,
) (bool, error) {
	raw, rawErr := f.decrypt(secret)
	if rawErr != nil {
		return false, rawErr
	}

	valid, validErr := totp.ValidateCustom(code, string(raw), time.Now().UTC(), totp.ValidateOpts{
		Period:    period,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})

	if validErr != nil {
		return false, validErr
	}

	return valid, nil
}

func (f *TwoFactor) GenerateRecoveryCodes() (*RecoveryCodes, error) {
	plains := make([]string, recoveryCodeCount)
	hashes := make([][]byte, recoveryCodeCount)

	for i := range recoveryCodeCount {
		b := make([]byte, recoveryCodeBytes)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		code := fmt.Sprintf("%X", b)
		plains[i] = fmt.Sprintf("%s-%s", code[0:5], code[5:10])

		hash, hashErr := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		if hashErr != nil {
			return nil, hashErr
		}
		hashes[i] = hash
	}

	return &RecoveryCodes{
		Plain: plains,
		Hash:  hashes,
	}, nil
}

func (f *TwoFactor) ValidateRecoveryCode(
	code string,
	codes []*repository.RecoveryCodesRow,
) (bool, uuid.UUID, time.Time) {
	for _, rc := range codes {
		if bcrypt.CompareHashAndPassword(rc.Code, []byte(code)) == nil {
			return true, rc.ID, rc.UpdatedAt
		}
	}
	return false, uuid.Nil, time.Time{}
}
