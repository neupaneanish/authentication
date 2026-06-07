//go:build unit

package utils_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"neupaneanish.com.np/api/internal/utils"
)

func TestValidateDomain(t *testing.T) {
	t.Parallel()

	txt := "DR2JTINSHENMG45HCADCSKYJZS"
	txtErr := "DR2JTINSHENMG45HCADCSKYJZA"
	url := "neupaneanish.com.np"

	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		domain, domainErr := utils.ValidateDomain(t.Context(), url, txt)
		require.NoError(t, domainErr)
		assert.NotNil(t, domain)
	})

	t.Run("Invalid TXT", func(t *testing.T) {
		t.Parallel()

		domain, domainErr := utils.ValidateDomain(t.Context(), url, txtErr)
		require.Error(t, domainErr)
		require.Empty(t, domain)
	})

	t.Run("Invalid host", func(t *testing.T) {
		t.Parallel()

		domain, domainErr := utils.ValidateDomain(t.Context(), "neupaneanish.co.np", txt)
		require.Error(t, domainErr)
		require.Empty(t, domain)
	})

	t.Run("Invalid URL", func(t *testing.T) {
		t.Parallel()

		domain, domainErr := utils.ValidateDomain(t.Context(), "neupane:anish.com.np", txt)
		require.Error(t, domainErr)
		require.Empty(t, domain)
	})
}
