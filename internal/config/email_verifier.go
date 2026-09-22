package config

import (
	"errors"
	"time"

	emailverifier "github.com/AfterShip/email-verifier"
)

type EmailVerifier struct {
	verifier       *emailverifier.Verifier
	allowFreeEmail bool
	allowRole      bool
}

const (
	emailVerifierContextTimeout = 3 * time.Second
)

func NewEmailVerifier(allowFreeEmail, allowRole bool) *EmailVerifier {
	verifier := emailverifier.NewVerifier().EnableAutoUpdateDisposable().ConnectTimeout(emailVerifierContextTimeout)
	return &EmailVerifier{
		verifier:       verifier,
		allowFreeEmail: allowFreeEmail,
		allowRole:      allowRole,
	}
}

func (v *EmailVerifier) Validate(email string) error {
	res, err := v.verifier.Verify(email)
	if err != nil {
		return err
	}
	if !res.Syntax.Valid {
		return errors.New("invalid email syntax")
	}

	if res.Disposable {
		return errors.New("disposable email not allowed")
	}

	if !res.HasMxRecords {
		return errors.New("no mx records found")
	}

	if !v.allowFreeEmail && res.Free {
		return errors.New("free email not allowed")
	}

	if !v.allowRole && res.RoleAccount {
		return errors.New("role-based email not allowed")
	}

	return nil
}
