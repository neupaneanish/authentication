//go:build integration

package service_test

import (
	"crypto/rand"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
	"neupaneanish.com.np/api/internal/errs"
	authv1 "neupaneanish.com.np/api/internal/protobuf/auth/v1"
	passwordv1 "neupaneanish.com.np/api/internal/protobuf/common/password/v1"
)

func TestRegister(t *testing.T) {
	t.Parallel()
	name := "Test Test"
	rawPassword := "Password@1234"
	dob := timestamppb.New(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))

	t.Run("Invalid Email", func(t *testing.T) {
		t.Parallel()
		req := &authv1.RegisterRequest{
			Name:            name,
			Email:           fmt.Sprintf("%s@test.com", rand.Text()),
			Password:        &passwordv1.Password{Value: rawPassword},
			ConfirmPassword: &passwordv1.Password{Value: rawPassword},
			Phone:           "+12121212121",
			Dob:             dob,
		}

		response, err := authServiceClient.Register(t.Context(), req)
		require.Error(t, err)
		assert.Equal(t, errs.ErrInvalidEmail, err)
		assert.Nil(t, response)
	})

	t.Run("Invalid Phone", func(t *testing.T) {
		t.Parallel()

		req := &authv1.RegisterRequest{
			Name:            name,
			Email:           cfg.Domain.GenerateEmail(rand.Text()),
			Password:        &passwordv1.Password{Value: rawPassword},
			ConfirmPassword: &passwordv1.Password{Value: rawPassword},
			Phone:           "+11234567890",
			Dob:             dob,
		}

		response, err := authServiceClient.Register(t.Context(), req)
		require.Error(t, err)
		assert.Equal(t, errs.ErrInvalidPhone, err)
		assert.Nil(t, response)
	})

	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		var idCounter uint64
		id := atomic.AddUint64(&idCounter, 1)

		email := cfg.Domain.GenerateEmail(rand.Text())
		phone := fmt.Sprintf("+1212%07d", 5000000+id)

		req := &authv1.RegisterRequest{
			Name:            name,
			Email:           email,
			Password:        &passwordv1.Password{Value: rawPassword},
			ConfirmPassword: &passwordv1.Password{Value: rawPassword},
			Phone:           phone,
			Dob:             dob,
		}

		response, err := authServiceClient.Register(t.Context(), req)
		require.NoError(t, err)
		assert.NotNil(t, response)

		t.Run("Unique Email Error", func(t *testing.T) {
			t.Parallel()

			emailReq := &authv1.RegisterRequest{
				Name:            name,
				Email:           email,
				Password:        &passwordv1.Password{Value: rawPassword},
				ConfirmPassword: &passwordv1.Password{Value: rawPassword},
				Phone:           phone,
				Dob:             dob,
			}

			emailRes, emailErr := authServiceClient.Register(t.Context(), emailReq)
			require.Error(t, emailErr)
			assert.Equal(t, errs.ErrEmailAlreadyExists, emailErr)
			assert.Nil(t, emailRes)
		})

		t.Run("Unique Phone Error", func(t *testing.T) {
			t.Parallel()

			phoneReq := &authv1.RegisterRequest{
				Name:            name,
				Email:           cfg.Domain.GenerateEmail(rand.Text()),
				Password:        &passwordv1.Password{Value: rawPassword},
				ConfirmPassword: &passwordv1.Password{Value: rawPassword},
				Phone:           phone,
				Dob:             dob,
			}

			phoneRes, phoneErr := authServiceClient.Register(t.Context(), phoneReq)
			require.Error(t, phoneErr)
			assert.Equal(t, errs.ErrPhoneAlreadyExists, phoneErr)
			assert.Nil(t, phoneRes)
		})
	})
}
