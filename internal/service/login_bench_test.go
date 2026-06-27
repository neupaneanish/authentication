//go:build benchmark

package service_test

import (
	"crypto/rand"
	"sync/atomic"
	"testing"

	"neupaneanish.com.np/authentication/internal/enum"
	passwordv1 "neupaneanish.com.np/authentication/internal/protobuf/common/password/v1"
	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"
)

func BenchmarkLogin(b *testing.B) {
	raw := "BenchPassword@123456"
	ctx := b.Context()

	requests := make([]*externalAuthenticationv1.LoginRequest, b.N)
	for i := 0; i < b.N; i++ {
		email := cfg.Domain.GenerateEmail(rand.Text())
		_, err := seedUser(ctx, email, raw, enum.UserStatusActive, true)
		if err != nil {
			b.Fatalf("Failed to pre-seed: %v", err)
		}
		requests[i] = &externalAuthenticationv1.LoginRequest{
			Email:    email,
			Password: &passwordv1.Password{Value: raw},
		}
	}

	var counter uint64
	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			idx := atomic.AddUint64(&counter, 1) - 1
			req := requests[idx%uint64(len(requests))]

			_, err := externalAuthenticationServiceClient.Login(ctx, req)
			if err != nil {
				b.Fatalf("Login failed: %v", err)
			}
		}
	})
}
