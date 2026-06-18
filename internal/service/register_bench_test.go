//go:build benchmark

package service_test

import (
	"crypto/rand"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
	authv1 "neupaneanish.com.np/api/internal/protobuf/auth/v1"
	passwordv1 "neupaneanish.com.np/api/internal/protobuf/common/password/v1"
)

var counter uint64

func BenchmarkRegister(b *testing.B) {
	requests := make([]*authv1.RegisterRequest, b.N)

	for i := 0; i < b.N; i++ {
		id := atomic.AddUint64(&counter, 1)
		phone := fmt.Sprintf("+97798041%d", 10000+id)
		requests[i] = &authv1.RegisterRequest{
			Name:            "Test Test",
			Email:           cfg.Domain.GenerateEmail(rand.Text()),
			Password:        &passwordv1.Password{Value: "Password@12345"},
			ConfirmPassword: &passwordv1.Password{Value: "Password@12345"},
			Phone:           phone,
			Dob:             timestamppb.New(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)),
		}
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			idx := atomic.AddUint64(&counter, 1) - 1
			req := requests[idx%uint64(len(requests))]

			_, err := authServiceClient.Register(b.Context(), req)
			if err != nil {
				b.Fatalf("Register Failed %v", err)
			}
		}
	})
}
