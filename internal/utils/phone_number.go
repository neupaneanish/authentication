package utils

import (
	"errors"
	"strings"

	"github.com/nyaruka/phonenumbers/v2"
)

func PhoneNumber(number string) (string, error) {
	if strings.TrimSpace(number) == "" {
		return "", errors.New("number cannot be empty")
	}

	phoneNumber, err := phonenumbers.Parse(number, "")
	if err != nil {
		return "", err
	}

	if !phonenumbers.IsValidNumber(phoneNumber) {
		return "", errors.New("invalid number")
	}

	num := phonenumbers.Format(phoneNumber, phonenumbers.E164)
	return num, nil
}
