//go:build unit

package enum_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"neupaneanish.com.np/api/internal/enum"
)

func TestUserStatus(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		status enum.UserStatus
		want   bool
	}{
		{
			name:   "valid active status",
			status: enum.UserStatusActive,
			want:   true,
		},
		{
			name:   "valid archived status",
			status: enum.UserStatusArchived,
			want:   true,
		},
		{
			name:   "valid deleted status",
			status: enum.UserStatusDeleted,
			want:   true,
		},
		{
			name:   "valid disabled status",
			status: enum.UserStatusDisabled,
			want:   true,
		},
		{
			name:   "valid locked status",
			status: enum.UserStatusLocked,
			want:   true,
		},
		{
			name:   "valid pending status",
			status: enum.UserStatusPending,
			want:   true,
		},
		{
			name:   "valid suspended status",
			status: enum.UserStatusSuspended,
			want:   true,
		},
		{
			name:   "invalid empty status",
			status: enum.UserStatus(""),
			want:   false,
		},
		{
			name:   "invalid random string",
			status: enum.UserStatus("test"),
			want:   false,
		},
		{
			name:   "invalid case sensitivity",
			status: enum.UserStatus("ACTIVE"),
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.status.Valid()
			assert.Equal(t, tt.want, got)
		})
	}
}
