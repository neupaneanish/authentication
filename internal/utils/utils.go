package utils

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"neupaneanish.com.np/authentication/internal/errs"
)

const (
	SessionExpiry        = time.Minute * 5
	AccessSessionExpiry  = 15 * time.Minute
	RefreshSessionExpiry = 7 * 24 * time.Hour

	EmailCodeBytes          = 4
	CredentialsHistoryLimit = 5
)

const (
	LoginTwoFactorSessionPrefix      = "login:two:factor:session"
	LoginAccessSessionPrefix         = "login:access:session"
	LoginRefreshSessionPrefix        = "login:refresh:session"
	ForgetPasswordSessionPrefix      = "forget:password:session"
	ResetPasswordSessionPrefix       = "reset:password:session"
	AccountVerificationSessionPrefix = "account:verification:session"
	ChangePasswordSessionPrefix      = "change:password:session"
	TwoFactorSessionPrefix           = "two:factor:session"
)

type LoginTwoFactorSession struct {
	Key    string    `json:"key"     valkey:",key"`
	Ver    int64     `json:"ver"     valkey:",ver"`
	ExAt   time.Time `json:"exat"    valkey:",exat"`
	UserID string    `json:"user_id"`
	Role   string    `json:"role"`
}

type LoginAccessSession struct {
	Key    string    `json:"key"     valkey:",key"`
	Ver    int64     `json:"ver"     valkey:",ver"`
	ExAt   time.Time `json:"exat"    valkey:",exat"`
	UserID string    `json:"user_id"`
}

type LoginRefreshSession struct {
	Key    string    `json:"key"     valkey:",key"`
	Ver    int64     `json:"ver"     valkey:",ver"`
	ExAt   time.Time `json:"exat"    valkey:",exat"`
	UserID string    `json:"user_id"`
	Role   string    `json:"role"`
	ID     string    `json:"id"`
}

type ForgetPasswordSession struct {
	Key    string    `json:"key"     valkey:",key"`
	Ver    int64     `json:"ver"     valkey:",ver"`
	ExAt   time.Time `json:"exat"    valkey:",exat"`
	UserID string    `json:"user_id"`
	Code   string    `json:"code"`
	Email  string    `json:"email"`
}

type GatewaySecuritySession struct {
	Key     string    `json:"key"     valkey:",key"`
	Ver     int64     `json:"ver"     valkey:",ver"`
	ExAt    time.Time `json:"exat"    valkey:",exat"`
	Session string    `json:"session"`
	Code    string    `json:"code"`
	Email   string    `json:"email"`
}

type ResetPasswordSession struct {
	Key    string    `json:"key"     valkey:",key"`
	Ver    int64     `json:"ver"     valkey:",ver"`
	ExAt   time.Time `json:"exat"    valkey:",exat"`
	UserID string    `json:"user_id"`
	Email  string    `json:"email"`
}

type AccountVerificationSession struct {
	Key       string    `json:"key"        valkey:",key"`
	Ver       int64     `json:"ver"        valkey:",ver"`
	ExAt      time.Time `json:"exat"       valkey:",exat"`
	UserID    string    `json:"user_id"`
	Role      string    `json:"role"`
	Method    string    `json:"method"`
	Code      string    `json:"code"`
	TwoFactor bool      `json:"two_factor"`
	Account   bool      `json:"account"`
	Email     string    `json:"email"`
}

type ContextKey string

const SessionKey ContextKey = "user_session"

type UserSession struct {
	UserID uuid.UUID
	Role   string
	Jti    string
}

func GetUserSessionContext(ctx context.Context, serviceName string, logger *slog.Logger) (*UserSession, error) {
	session, ok := ctx.Value(SessionKey).(*UserSession)
	if ok {
		return session, nil
	}
	logger.ErrorContext(ctx, "invalid User Session from context", "service", serviceName)
	return nil, errs.ErrPermissionDenied
}
