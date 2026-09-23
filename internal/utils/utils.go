package utils

import (
	"context"
	"time"

	"uuid"
)

const (
	SessionExpiry        = time.Minute * 5
	AccessSessionExpiry  = 15 * time.Minute
	RefreshSessionExpiry = 7 * 24 * time.Hour

	EmailCodeBytes          = 4
	CredentialsHistoryLimit = 5
)

const (
	LoginAccessSessionPrefix          = "login:access:session"
	LoginRefreshSessionPrefix         = "login:refresh:session"
	ResetPasswordSessionPrefix        = "reset:password:session"
	ChangePasswordSessionPrefix       = "change:password:session"
	TwoFactorSessionPrefix            = "two:factor:session"
	PasswordVerificationSessionPrefix = "password:verification:session"
	UserSessionPrefix                 = "user:session:"
	VerificationSessionPrefix         = "verification:session"

	EmailTemplateAccountVerification    = "account-verification"
	EmailTemplateForgetPassword         = "forget-password"
	EmailTemplateEmailVerification      = "email-verification"
	EmailTemplatePasswordReset          = "password-reset"
	EmailTemplateChangePassword         = "change-password"
	EmailTemplateEnableTwoFactor        = "enable-two-factor"
	EmailTemplateDisableTwoFactor       = "disable-two-factor"
	EmailTemplateConfirmChangePassword  = "confirm-change-password"
	EmailTemplateConfirmTwoFactor       = "confirm-two-factor"
	EmailTemplateConfirmDeleteTwoFactor = "confirm-delete-two-factor"

	RedpandaAuthEmailNotificationTopic     = "auth-email-notification"
	RedpandaSecurityEmailNotificationTopic = "security-email-notification"
	RedpandaRootNotificationTopic          = "root-notification"
)

type LoginAccessSession struct {
	Key     string    `json:"key"     valkey:",key"`
	Ver     int64     `json:"ver"     valkey:",ver"`
	ExAt    time.Time `json:"exat"    valkey:",exat"`
	UserID  string    `json:"user_id"`
	Role    string    `json:"role"`
	Refresh string    `json:"refresh"`
}

type LoginRefreshSession struct {
	Key    string    `json:"key"     valkey:",key"`
	Ver    int64     `json:"ver"     valkey:",ver"`
	ExAt   time.Time `json:"exat"    valkey:",exat"`
	UserID string    `json:"user_id"`
	Role   string    `json:"role"`
	ID     string    `json:"id"`
}

type PasswordVerificationSession struct {
	Key     string    `json:"key"     valkey:",key"`
	Ver     int64     `json:"ver"     valkey:",ver"`
	ExAt    time.Time `json:"exat"    valkey:",exat"`
	Session string    `json:"session"`
	Code    string    `json:"code"`
	Email   string    `json:"email"`
	Method  string    `json:"method"`
}

type ChangePasswordSession struct {
	Key     string    `json:"key"     valkey:",key"`
	Ver     int64     `json:"ver"     valkey:",ver"`
	ExAt    time.Time `json:"exat"    valkey:",exat"`
	Session string    `json:"session"`
	Email   string    `json:"email"`
}

type EnableTwoFactorSession struct {
	Key     string    `json:"key"     valkey:",key"`
	Ver     int64     `json:"ver"     valkey:",ver"`
	ExAt    time.Time `json:"exat"    valkey:",exat"`
	Session string    `json:"session"`
	Email   string    `json:"email"`
	Secret  []byte    `json:"secret"`
}

type ResetPasswordSession struct {
	Key    string    `json:"key"     valkey:",key"`
	Ver    int64     `json:"ver"     valkey:",ver"`
	ExAt   time.Time `json:"exat"    valkey:",exat"`
	UserID string    `json:"user_id"`
	Email  string    `json:"email"`
}

type VerificationSession struct {
	Key                string    `json:"key"                valkey:",key"`
	Ver                int64     `json:"ver"                valkey:",ver"`
	ExAt               time.Time `json:"exat"               valkey:",exat"`
	UserID             string    `json:"user_id"`
	Role               string    `json:"role"`
	Method             string    `json:"method"`
	VerificationMethod string    `json:"VerificationMethod"`
	Code               string    `json:"code"`
	Email              string    `json:"email"`
	EnabledTwoFactor   bool      `json:"enabledTwoFactor"`
}

type AuthEmail struct {
	Value         string
	Email         string
	EmailTemplate string
}

type SecurityEmail struct {
	Email         string
	EmailTemplate string
}

type RootNotification struct {
	ActorID  uuid.UUID
	UserID   uuid.UUID
	Username string
	Table    string
	Method   string
}

type ContextKey string

const SessionKey ContextKey = "user_session"

type UserSession struct {
	UserID uuid.UUID
	Jti    string
}

func UserSessionContext(ctx context.Context) *UserSession {
	session, _ := ctx.Value(SessionKey).(*UserSession)
	return session
}
