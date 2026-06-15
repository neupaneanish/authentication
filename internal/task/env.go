package task

import (
	"fmt"

	"neupaneanish.com.np/api/internal/domain"
	"neupaneanish.com.np/api/internal/env"
)

type Env struct {
	ValkeyURL   string
	SMTP2GO     string
	SenderEmail string
}

func LoadWorkerEnv() (*Env, error) {
	valkeyURL, valkeyURLErr := env.ValidateEnv("VALKEY_URL")
	if valkeyURLErr != nil {
		return nil, valkeyURLErr
	}

	smtp2go, smtp2goErr := env.ValidateEnv("SMTP2GO_API")
	if smtp2goErr != nil {
		return nil, smtp2goErr
	}

	senderURL, senderURLErr := env.ValidateEnv("SENDER_URL")
	if senderURLErr != nil {
		return nil, senderURLErr
	}
	url, urlErr := domain.ValidateDomain(senderURL)
	if urlErr != nil {
		return nil, urlErr
	}

	return &Env{
		ValkeyURL:   valkeyURL,
		SMTP2GO:     smtp2go,
		SenderEmail: fmt.Sprintf("no-reply@%s", url),
	}, nil
}
