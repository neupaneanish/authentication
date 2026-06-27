//go:build integration

package service_test

import (
	"crypto/rand"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"neupaneanish.com.np/authentication/internal/errs"
	passwordv1 "neupaneanish.com.np/authentication/internal/protobuf/common/password/v1"
	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"
)

func TestRegister(t *testing.T) {
	t.Parallel()
	rawPassword := "Password@1234"

	t.Run("Invalid Email", func(t *testing.T) {
		t.Parallel()
		req := &externalAuthenticationv1.RegisterRequest{
			Email:           fmt.Sprintf("%s@test.com", rand.Text()),
			Password:        &passwordv1.Password{Value: rawPassword},
			ConfirmPassword: &passwordv1.Password{Value: rawPassword},
			Phone:           "+12121212121",
		}

		response, err := externalAuthenticationServiceClient.Register(t.Context(), req)
		require.Error(t, err)
		assert.Equal(t, errs.ErrInvalidEmail, err)
		assert.Nil(t, response)
	})

	t.Run("Invalid Phone", func(t *testing.T) {
		t.Parallel()

		req := &externalAuthenticationv1.RegisterRequest{
			Email:           cfg.Domain.GenerateEmail(rand.Text()),
			Password:        &passwordv1.Password{Value: rawPassword},
			ConfirmPassword: &passwordv1.Password{Value: rawPassword},
			Phone:           "+11234567890",
		}

		response, err := externalAuthenticationServiceClient.Register(t.Context(), req)
		require.Error(t, err)
		assert.Equal(t, errs.ErrInvalidPhone, err)
		assert.Nil(t, response)
	})

	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		id := atomic.AddUint64(&phoneCounter, 1)

		email := cfg.Domain.GenerateEmail(rand.Text())
		phone := fmt.Sprintf("+1212%07d", 5000000+id)

		req := &externalAuthenticationv1.RegisterRequest{
			Email:           email,
			Password:        &passwordv1.Password{Value: rawPassword},
			ConfirmPassword: &passwordv1.Password{Value: rawPassword},
			Phone:           phone,
		}

		response, err := externalAuthenticationServiceClient.Register(t.Context(), req)
		require.NoError(t, err)
		assert.NotNil(t, response)

		t.Run("Unique Email Error", func(t *testing.T) {
			t.Parallel()

			emailReq := &externalAuthenticationv1.RegisterRequest{
				Email:           email,
				Password:        &passwordv1.Password{Value: rawPassword},
				ConfirmPassword: &passwordv1.Password{Value: rawPassword},
				Phone:           phone,
			}

			emailRes, emailErr := externalAuthenticationServiceClient.Register(t.Context(), emailReq)
			require.Error(t, emailErr)
			assert.Equal(t, errs.ErrEmailAlreadyExists, emailErr)
			assert.Nil(t, emailRes)
		})

		t.Run("Unique Phone Error", func(t *testing.T) {
			t.Parallel()

			phoneReq := &externalAuthenticationv1.RegisterRequest{
				Email:           cfg.Domain.GenerateEmail(rand.Text()),
				Password:        &passwordv1.Password{Value: rawPassword},
				ConfirmPassword: &passwordv1.Password{Value: rawPassword},
				Phone:           phone,
			}

			phoneRes, phoneErr := externalAuthenticationServiceClient.Register(t.Context(), phoneReq)
			require.Error(t, phoneErr)
			assert.Equal(t, errs.ErrPhoneAlreadyExists, phoneErr)
			assert.Nil(t, phoneRes)
		})
	})
}
