//go:build benchmark

package service_test

import (
	"crypto/rand"
	"fmt"
	"sync/atomic"
	"testing"

	passwordv1 "neupaneanish.com.np/authentication/internal/protobuf/common/password/v1"
	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"
)

func BenchmarkRegister(b *testing.B) {
	requests := make([]*externalAuthenticationv1.RegisterRequest, b.N)

	for i := 0; i < b.N; i++ {
		id := atomic.AddUint64(&phoneCounter, 1)
		phone := fmt.Sprintf("+97798041%d", 10000+id)
		requests[i] = &externalAuthenticationv1.RegisterRequest{
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

			_, err := externalAuthenticationServiceClient.Register(b.Context(), req)
			if err != nil {
				b.Fatalf("Register Failed %v", err)
			}
		}
	})
}
