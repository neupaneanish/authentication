package utils

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"uuid"

	"github.com/valkey-io/valkey-go"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/timestamppb"

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
	systemUsername = "system"

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
	ActorID       uuid.UUID
	UserID        uuid.UUID
	ActorUsername string
	UserUsername  string
	Table         string
	Method        string
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

func TimestamppbValue(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func GetUsernames(
	ctx context.Context,
	createdBy, updatedBy uuid.UUID,
	session *UserSession,
	client valkey.Client,
	logger *slog.Logger,
) (string, string, error) {
	if createdBy == updatedBy && createdBy == uuid.Nil() {
		return systemUsername, systemUsername, nil
	}

	if session.UserID == createdBy && createdBy == updatedBy {
		return session.Username, session.Username, nil
	}

	var createdUsername, updateUsername string

	g, gCtx := errgroup.WithContext(ctx)

	g.Go(func() error {
		if session.UserID == createdBy {
			createdUsername = session.Username
			return nil
		}

		username, err := getUsername(gCtx, createdBy, client)
		if err != nil {
			return err
		}
		createdUsername = username
		return nil
	})

	g.Go(func() error {
		if session.UserID == updatedBy {
			updateUsername = session.Username
			return nil
		}

		username, err := getUsername(gCtx, updatedBy, client)
		if err != nil {
			return err
		}
		updateUsername = username
		return nil
	})

	if err := g.Wait(); err != nil {
		logger.ErrorContext(ctx, "Failed to get username", "error", err)
		return "", "", errs.ErrInternalServer
	}

	return createdUsername, updateUsername, nil
}

func getUsername(ctx context.Context, userID uuid.UUID, client valkey.Client) (string, error) {
	if userID == uuid.Nil() {
		return systemUsername, nil
	}

	key := fmt.Sprintf("user:username:%s", userID.String())
	cmd := client.B().Get().Key(key).Build()

	value, err := client.Do(ctx, cmd).ToString()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			return "notfound", nil
		}
		return "unknown", err
	}
	return value, nil
}
