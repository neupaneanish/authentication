package config

import (
	"fmt"
	"strings"
)

type Domain struct {
	URL string
	API string
}

func NewDomain(domain string, api string) *Domain {
	return &Domain{
		URL: domain,
		API: api,
	}
}

func (d *Domain) ValidateEmail(email string) bool {
	suffix := fmt.Sprintf("@%s", d.URL)
	return strings.HasSuffix(strings.ToLower(email), suffix)
}

func (d *Domain) GenerateUsername(email string) string {
	suffix := fmt.Sprintf("@%s", d.URL)
	return strings.TrimSuffix(strings.ToLower(email), suffix)
}

func (d *Domain) GenerateEmail(username string) string {
	return fmt.Sprintf("%s@%s", strings.ToLower(username), d.URL)
}
