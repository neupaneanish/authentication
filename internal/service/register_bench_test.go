//go:build benchmark

package service_test

import (
	"fmt"
	"math/rand"
	"testing"

	passwordv1 "neupaneanish.com.np/authentication/internal/protobuf/common/authentication/v1"
	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"
)

func BenchmarkRegister(b *testing.B) {
	requests := make([]*externalAuthenticationv1.RegisterRequest, b.N)

	for i := range b.N {
		id := phoneCounter.Add(1)
		phone := fmt.Sprintf("+97798041%d", 10000+id)
		username := fmt.Sprintf("username%d", rand.Int63n(1000000))
		requests[i] = &externalAuthenticationv1.RegisterRequest{
			Email:           generateEmail(),
			Password:        &passwordv1.Password{Value: "Password@12345"},
			ConfirmPassword: &passwordv1.Password{Value: "Password@12345"},
			Phone:           phone,
			Username:        username,
		}
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			idx := phoneCounter.Add(1) - 1
			req := requests[idx%uint64(len(requests))]

			_, err := externalAuthenticationServiceClient.Register(b.Context(), req)
			if err != nil {
				b.Fatalf("Register Failed %v", err)
			}
		}
	})
}
