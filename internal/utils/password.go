package utils

import (
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func ComparePassword(hash []byte, raw string) bool {
	if strings.TrimSpace(raw) == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword(hash, []byte(raw)) == nil
}

func CreatePassword(raw string) ([]byte, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("password cannot be empty")
	}
	hash, hashErr := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.DefaultCost)
	if hashErr != nil {
		return nil, hashErr
	}
	return hash, nil
}
