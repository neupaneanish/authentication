//go:build unit

package enum_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"neupaneanish.com.np/authentication/internal/enum"
)

func TestMethod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method enum.Method
		want   bool
	}{
		{
			name:   "Valid login",
			method: enum.MethodLogin,
			want:   true,
		},
		{
			name:   "Valid forget password",
			method: enum.MethodForgetPassword,
			want:   true,
		},
		{
			name:   "Valid register",
			method: enum.MethodRegister,
			want:   true,
		}, {
			name:   "invalid method",
			method: enum.Method(""),
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.method.Valid()
			assert.Equal(t, tt.want, got)
		})
	}
}
