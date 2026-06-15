package domain

import (
	"context"
	"errors"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"
)

const lookupCtxTimeout = 2 * time.Second

func ValidateDomain(domain string) (string, error) {
	input := strings.ToLower(domain)

	if !strings.HasPrefix(input, "http://") && !strings.HasPrefix(input, "https://") {
		input = "https://" + input
	}

	parsed, parsedErr := url.Parse(input)
	if parsedErr != nil {
		return "", errors.New("malformed domain format string")
	}

	return parsed.Hostname(), nil
}

func ValidateDomainWithTXT(ctx context.Context, domain string, verification string) (string, error) {
	cleanDomain, cleanDomainErr := ValidateDomain(domain)
	if cleanDomainErr != nil {
		return "", cleanDomainErr
	}

	lookupCtx, cancel := context.WithTimeout(ctx, lookupCtxTimeout)
	defer cancel()

	var r net.Resolver

	txtRecords, err := r.LookupTXT(lookupCtx, cleanDomain)
	if err != nil || len(txtRecords) == 0 {
		return "", errors.New("domain verification failed: host unreachable or no public TXT records found")
	}

	target := strings.TrimSpace(verification)
	if slices.Contains(txtRecords, target) {
		return cleanDomain, nil
	}
	return "", errors.New("domain ownership verification failed: matching token not found in TXT pool")
}
