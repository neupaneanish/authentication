package utils

import (
	"context"
	"log/slog"
	"time"

	"uuid"

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
	LoginAccessSessionPrefix          = "login:access:session"
	LoginRefreshSessionPrefix         = "login:refresh:session"
	ResetPasswordSessionPrefix        = "reset:password:session"
	ChangePasswordSessionPrefix       = "change:password:session"
	ChangeEmailSessionPrefix          = "change:email:session"
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
	EmailTemplateChangeEmail            = "change-email"
	EmailTemplateSuccessChangeEmail     = "success-change-email"

	DatabaseTableUser       = "user"
	DatabaseTableCredential = "credential"
	DatabaseTableTwoFactor  = "twofactor"

	DatabaseMethodCreate = "create"
	DatabaseMethodUpdate = "update"
	DatabaseMethodDelete = "delete"
	DatabaseMethodReset  = "reset"

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

type ChangeEmailSession struct {
	Key     string    `json:"key"     valkey:",key"`
	Ver     int64     `json:"ver"     valkey:",ver"`
	ExAt    time.Time `json:"exat"    valkey:",exat"`
	Session string    `json:"session"`
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
	Key      string    `json:"key"      valkey:",key"`
	Ver      int64     `json:"ver"      valkey:",ver"`
	ExAt     time.Time `json:"exat"     valkey:",exat"`
	UserID   string    `json:"user_id"`
	Email    string    `json:"email"`
	Username string    `json:"username"`
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
	Username           string    `json:"username"`
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
	UserID   uuid.UUID
	Username string
	Jti      string
}

func UserSessionContext(ctx context.Context) *UserSession {
	session, _ := ctx.Value(SessionKey).(*UserSession)
	return session
}

func ParsedUUID(ctx context.Context, id, serviceName string, logger *slog.Logger) (uuid.UUID, error) {
	idx, err := uuid.Parse(id)
	if err != nil {
		logger.ErrorContext(
			ctx,
			"Invalid User ID",
			"service", serviceName,
			"userID", id,
			"error", err,
		)
		return uuid.Nil(), errs.ErrNotFound
	}
	return idx, nil
}
