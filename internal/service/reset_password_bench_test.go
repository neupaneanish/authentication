//go:build benchmark

package service_test

import (
	"crypto/rand"
	"sync/atomic"
	"testing"
	"time"

	"neupaneanish.com.np/authentication/internal/enum"
	passwordv1 "neupaneanish.com.np/authentication/internal/protobuf/common/password/v1"
	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"
	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/internal/utils"
)

func BenchmarkResetPassword(b *testing.B) {
	ctx := b.Context()
	oldPassword := "Bench@Password1"
	newPassword := "Bench@Password12"

	requests := make([]*externalAuthenticationv1.ResetPasswordRequest, b.N)
	for i := 0; i < b.N; i++ {
		email := cfg.Domain.GenerateEmail(rand.Text())
		userID, err := seedUser(ctx, email, oldPassword, enum.UserStatusActive, true)
		if err != nil {
			b.Fatalf("Failed to pre-seed benchmark user: %v", err)
		}

		session := rand.Text()
		data := &utils.ResetPasswordSession{
			Key:    session,
			ExAt:   time.Now().Add(utils.SessionExpiry),
			UserID: userID,
		}

		hSetErr := redis.HSet[utils.ResetPasswordSession](ctx, utils.ResetPasswordSessionPrefix, data, cfg.Client)
		if hSetErr != nil {
			b.Fatalf("Failed to seed session %v", hSetErr)
		}

		requests[i] = &externalAuthenticationv1.ResetPasswordRequest{
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

			_, err := externalAuthenticationServiceClient.ResetPassword(ctx, req)
			if err != nil {
				b.Fatalf("ResetPassword failed %v", err)
			}
		}
	})
}
