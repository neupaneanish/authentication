//go:build unit

package domain_test

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"neupaneanish.com.np/api/internal/domain"
)

func TestDomain(t *testing.T) {
	t.Parallel()
	t.Run("Validate domain with txt", func(t *testing.T) {
		t.Parallel()

		t.Run("malformed", func(t *testing.T) {
			t.Parallel()
			url, urlErr := domain.ValidateDomainWithTXT(t.Context(), "neupane:anish.com.np", rand.Text())
			require.Error(t, urlErr)
			assert.Empty(t, url)
		})

		t.Run("No txt", func(t *testing.T) {
			t.Parallel()
			url, urlErr := domain.ValidateDomainWithTXT(t.Context(), "anishneupane.com.np", rand.Text())
			require.Error(t, urlErr)
			assert.Empty(t, url)
		})

		t.Run("Success", func(t *testing.T) {
			t.Parallel()
			txt := "DR2JTINSHENMG45HCADCSKYJZS"
			url, urlErr := domain.ValidateDomainWithTXT(t.Context(), "neupaneanish.com.np", txt)
			require.NoError(t, urlErr)
			assert.Equal(t, url, "neupaneanish.com.np")
		})

		t.Run("Invalid Txt", func(t *testing.T) {
			t.Parallel()
			url, urlErr := domain.ValidateDomainWithTXT(t.Context(), "neupaneanish.com.np", rand.Text())
			require.Error(t, urlErr)
			assert.Empty(t, url)
		})
	})
}
