//go:build unit

package enum_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"neupaneanish.com.np/api/internal/enum"
)

func TestUserRole(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		role enum.UserRole
		want bool
	}{
		{
			name: "valid root role",
			role: enum.UserRoleRoot,
			want: true,
		},
		{
			name: "valid user role",
			role: enum.UserRoleUser,
			want: true,
		},
		{
			name: "invalid empty role",
			role: enum.UserRole(""),
			want: false,
		},
		{
			name: "invalid random string",
			role: enum.UserRole("admin"),
			want: false,
		},
		{
			name: "invalid case sensitivity",
			role: enum.UserRole("ROOT"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.role.Valid()
			assert.Equal(t, tt.want, got)
		})
	}
}
