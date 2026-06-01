//go:build benchmark

package service_test

import (
	"crypto/rand"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	authv1 "neupaneanish.com.np/api/internal/protobuf/auth/v1"
	passwordv1 "neupaneanish.com.np/api/internal/protobuf/common/password/v1"
	"neupaneanish.com.np/api/internal/redis"
	"neupaneanish.com.np/api/internal/service"
)

func BenchmarkResetPassword(b *testing.B) {
	ctx := b.Context()
	oldPassword := "Bench@Password1"
	newPassword := "Bench@Password12"

	requests := make([]*authv1.ResetPasswordRequest, b.N)
	for i := 0; i < b.N; i++ {
		email := fmt.Sprintf("%s@test.com", rand.Text())
		userID, err := seedUser(ctx, email, oldPassword)
		if err != nil {
			b.Fatalf("Failed to pre-seed benchmark user: %v", err)
		}

		session := rand.Text()
		data := &service.ResetPasswordSession{
			Key:    session,
			ExAt:   time.Now().Add(service.SessionExpiry),
			UserID: userID,
		}

		hSetErr := redis.HSet[service.ResetPasswordSession](ctx, service.ResetPasswordSessionPrefix, data, cfg.Client)
		if hSetErr != nil {
			b.Fatalf("Failed to seed session %v", hSetErr)
		}

		requests[i] = &authv1.ResetPasswordRequest{
			Session:         session,
			Password:        &passwordv1.Password{Value: newPassword},
			ConfirmPassword: &passwordv1.Password{Value: newPassword},
		}
	}

	var counter uint64
	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			idx := atomic.AddUint64(&counter, 1) - 1
			req := requests[idx%uint64(len(requests))]

			_, err := authServiceClient.ResetPassword(ctx, req)
			if err != nil {
				b.Fatalf("ResetPassword failed %v", err)
			}
		}
	})
}
