//go:build benchmark

package service_test

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	authv1 "neupaneanish.com.np/api/internal/protobuf/auth/v1"
	passwordv1 "neupaneanish.com.np/api/internal/protobuf/common/password/v1"
)

func BenchmarkLogin(b *testing.B) {
	raw := "BenchPassword@123456"
	bytes := make([]byte, 4)
	_, _ = rand.Read(bytes)
	runID := hex.EncodeToString(bytes)

	b.StopTimer()

	for i := 0; i < b.N; i++ {
		email := fmt.Sprintf("email_%s_%d@test.com", runID, i)
		err := seedUser(b.Context(), email, raw)
		if err != nil {
			b.Fatalf("Failed to pre-seed benchmark user at index %d: %v", i, err)
		}
	}

	b.StartTimer()

	for i := 0; i < b.N; i++ {
		email := fmt.Sprintf("email_%s_%d@test.com", runID, i)

		req := &authv1.LoginRequest{
			Email:    email,
			Password: &passwordv1.Password{Value: raw},
		}
		_, err := authServiceClient.Login(b.Context(), req)
		if err != nil {
			b.Fatalf("Login failed at iteration %d: %v", i, err)
		}
	}
}
