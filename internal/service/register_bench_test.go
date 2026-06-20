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

func BenchmarkRegister(b *testing.B) {
	requests := make([]*authv1.RegisterRequest, b.N)

	for i := 0; i < b.N; i++ {
		id := atomic.AddUint64(&phoneCounter, 1)
		phone := fmt.Sprintf("+97798041%d", 10000+id)
		requests[i] = &authv1.RegisterRequest{
			Email:           cfg.Domain.GenerateEmail(rand.Text()),
			Password:        &passwordv1.Password{Value: "Password@12345"},
			ConfirmPassword: &passwordv1.Password{Value: "Password@12345"},
			Phone:           phone,
		}
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			idx := atomic.AddUint64(&phoneCounter, 1) - 1
			req := requests[idx%uint64(len(requests))]

			_, err := authServiceClient.Register(b.Context(), req)
			if err != nil {
				b.Fatalf("Register Failed %v", err)
			}
		}
	})
}
