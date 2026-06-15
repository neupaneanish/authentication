package utils

import "time"

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
}
