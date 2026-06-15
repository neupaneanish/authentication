//go:build unit

package config_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"neupaneanish.com.np/api/internal/config"
)

func TestNewDomain(t *testing.T) {
	t.Parallel()
	domain := config.NewDomain("neupaneanish.com.np", "api.neupaneanish.com.np")

	t.Run("Validate Email Success", func(t *testing.T) {
		t.Parallel()

		ok := domain.ValidateEmail("test@neupaneanish.com.np")
		assert.True(t, ok)
	})

	t.Run("Validate Email Failed", func(t *testing.T) {
		t.Parallel()

		ok := domain.ValidateEmail("test@neupaneanish.com")
		assert.False(t, ok)
	})

	t.Run("Generate Username", func(t *testing.T) {
		t.Parallel()
		email := "test@neupaneanish.com.np"
		username := domain.GenerateUsername(email)

		assert.Equal(t, username, strings.TrimSuffix(email, fmt.Sprintf("@%s", domain.URL)))
	})

	t.Run("Generate Email", func(t *testing.T) {
		t.Parallel()
		username := "test"
		email := domain.GenerateEmail(username)

		assert.Equal(t, email, fmt.Sprintf("%s@%s", username, domain.URL))
	})
}
