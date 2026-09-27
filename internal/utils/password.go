package utils

import (
	"bufio"
	"context"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"neupaneanish.com.np/authentication/internal/errs"
)

const (
	pwnedContextTimeout = 2 * time.Second
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

func PasswordPwned(ctx context.Context, password, serviceName string, logger *slog.Logger) error {
	newCtx, cancel := context.WithTimeout(ctx, pwnedContextTimeout)
	defer cancel()

	hasher := sha1.New()
	hasher.Write([]byte(password))
	hash := fmt.Sprintf("%X", hasher.Sum(nil))

	prefix := hash[:5]
	suffix := hash[5:]

	url := "https://api.pwnedpasswords.com/range/" + prefix

	req, reqErr := http.NewRequestWithContext(newCtx, http.MethodGet, url, nil)
	if reqErr != nil {
		logger.ErrorContext(ctx, "failed to initialize req", "service", serviceName, "error", reqErr)
		return errs.ErrInternalServer
	}

	req.Header.Set("User-Agent", "Go-Pwned-Validator")

	resp, resErr := http.DefaultClient.Do(req)
	if resErr != nil {
		logger.ErrorContext(ctx, "failed to request client", "service", serviceName, "error", resErr)
		return errs.ErrInternalServer
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		logger.ErrorContext(
			ctx,
			"unexpected HIBP status response",
			"service",
			serviceName,
			"status_code",
			resp.StatusCode,
		)
		return errs.ErrInternalServer
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()

		before, after, found := strings.Cut(line, ":")

		if found && before == suffix {
			logger.WarnContext(ctx, "Password Pwned", "service", serviceName, "count", after)
			return errs.ErrPasswordPwned
		}
	}

	if err := scanner.Err(); err != nil {
		logger.ErrorContext(ctx, "scanner error reading HIBP response", "service", serviceName, "error", err)
		return errs.ErrInternalServer
	}

	return nil
}
