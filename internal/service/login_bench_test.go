//go:build benchmark

package service_test

import (
	"crypto/rand"
	"fmt"
	"sync/atomic"
	"testing"

	authv1 "neupaneanish.com.np/api/internal/protobuf/auth/v1"
	passwordv1 "neupaneanish.com.np/api/internal/protobuf/common/password/v1"
)

func BenchmarkLogin(b *testing.B) {
	raw := "BenchPassword@123456"
	ctx := b.Context()

	requests := make([]*authv1.LoginRequest, b.N)
	for i := 0; i < b.N; i++ {
		email := fmt.Sprintf("%s@test.com", rand.Text())
		_, err := seedUser(ctx, email, raw)
		if err != nil {
			b.Fatalf("Failed to pre-seed: %v", err)
		}
		requests[i] = &authv1.LoginRequest{
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

			_, err := authServiceClient.Login(ctx, req)
			if err != nil {
				b.Fatalf("Login failed: %v", err)
			}
		}
	})
}
