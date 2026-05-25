package config_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"neupaneanish.com.np/api/internal/config"
)

func TestNewTwoFactor(t *testing.T) {
	t.Parallel()
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	assert.NotNil(t, privateKey)

	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		tf, tfErr := config.NewTwoFactor(hex.EncodeToString(privateKey.Seed()), "Test")
		require.NoError(t, tfErr)
		assert.NotNil(t, tf)

		t.Run("Generate", func(t *testing.T) {
			t.Parallel()
			data, dataErr := tf.Generate("test@test")
			require.NoError(t, dataErr)
			assert.NotNil(t, data)

			t.Run("Encrypt", func(t *testing.T) {
				t.Parallel()
				encrypt, encryptErr := tf.Encrypt(data.Secret)
				require.NoError(t, encryptErr)
				require.NotNil(t, encrypt)

				t.Run("Validate", func(t *testing.T) {
					t.Parallel()
					code, codeErr := totp.GenerateCode(data.Secret, time.Now())
					require.NoError(t, codeErr)
					assert.NotNil(t, code)

					ok, validateErr := tf.Validate(code, encrypt)
					require.NoError(t, validateErr)
					assert.True(t, ok)
				})

				t.Run("Invalid Code", func(t *testing.T) {
					t.Parallel()
					ok, validateErr := tf.Validate("123456", encrypt)
					require.NoError(t, validateErr)
					assert.False(t, ok)
				})
			})
		})

		t.Run("Recovery Code", func(t *testing.T) {
			t.Parallel()
			recovery, recoveryErr := tf.GenerateRecoveryCodes()
			require.NoError(t, recoveryErr)
			assert.Len(t, recovery.Hash, 10)
			assert.Len(t, recovery.Plain, 10)

			t.Run("Validate Code", func(t *testing.T) {
				t.Parallel()
				cleanCode := strings.ReplaceAll(recovery.Plain[0], "-", "")
				compareErr := bcrypt.CompareHashAndPassword(recovery.Hash[0], []byte(cleanCode))
				require.NoError(t, compareErr)
			})

			t.Run("Invalid Code", func(t *testing.T) {
				t.Parallel()
				compareErr := bcrypt.CompareHashAndPassword(recovery.Hash[0], []byte(recovery.Plain[0]))
				require.Error(t, compareErr)
			})
		})
	})

	t.Run("Invalid Key", func(t *testing.T) {
		t.Parallel()
		tf, tfErr := config.NewTwoFactor(hex.EncodeToString(privateKey), "Test")
		require.Error(t, tfErr)
		assert.Nil(t, tf)
	})
}
