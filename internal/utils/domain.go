package utils

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"
)

const lookupCtxTimeout = 2 * time.Second

func ValidateDomain(ctx context.Context, domain string, verification string) (string, error) {
	input := strings.ToLower(domain)

	if !strings.HasPrefix(input, "http://") && !strings.HasPrefix(input, "https://") {
		input = "https://" + input
	}

	parsed, parseErr := url.Parse(input)
	if parseErr != nil {
		return "", errors.New("malformed domain format string")
	}

	cleanDomain := parsed.Hostname()

	lookupCtx, cancel := context.WithTimeout(ctx, lookupCtxTimeout)
	defer cancel()

	var r net.Resolver

	txtRecords, err := r.LookupTXT(lookupCtx, cleanDomain)
	if err != nil || len(txtRecords) == 0 {
		return "", errors.New("domain verification failed: host unreachable or no public TXT records found")
	}

	for _, txt := range txtRecords {
		if txt == verification {
			return cleanDomain, nil
		}
	}
	return "", errors.New("domain ownership verification failed: matching token not found in TXT pool")
}
