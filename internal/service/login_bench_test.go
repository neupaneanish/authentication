//go:build benchmark

package service_test

import (
	"crypto/rand"
	"fmt"
	"testing"

	authv1 "neupaneanish.com.np/api/internal/protobuf/auth/v1"
	passwordv1 "neupaneanish.com.np/api/internal/protobuf/common/password/v1"
)

func BenchmarkLogin(b *testing.B) {
	raw := "BenchPassword@123456"

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		b.StopTimer()
		email := fmt.Sprintf("%s@test.com", rand.Text())
		_, err := seedUser(b.Context(), email, raw)
		if err != nil {
			b.Fatalf("Failed to pre-seed benchmark user: %v", err)
		}
		req := &authv1.LoginRequest{
			Email:    email,
			Password: &passwordv1.Password{Value: raw},
		}

		b.StartTimer()
		_, responseErr := authServiceClient.Login(b.Context(), req)
		if responseErr != nil {
			b.Fatalf("Login failed at iteration: %v", responseErr)
		}
	}
}
