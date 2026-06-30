package task

import (
	"encoding/json"
	"time"

	"github.com/hibiken/asynq"
)

const (
	TypeAccountVerification = "account-verification"
	TypeForgetPassword      = "forget-password"
	TypeEmailVerification   = "email-verification"
	TypePasswordReset       = "password-reset"
	TypeChangePassword      = "change-password"
	TypePasswordChanged     = "password-changed"
	TypeTwoFactor           = "two-factor"

	maxRetry     = 5
	asyncTimeout = 20 * time.Second
)

type EmailTaskPayload struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

type SecurityEmailTaskPayload struct {
	Email string `json:"email"`
}

func AuthEmailTask(taskType string, email string, code string) (*asynq.Task, error) {
	payload, err := json.Marshal(EmailTaskPayload{
		Email: email,
		Code:  code,
	})
	return PayloadTask(payload, taskType, err)
}

func SecurityNotification(taskType string, email string) (*asynq.Task, error) {
	payload, err := json.Marshal(SecurityEmailTaskPayload{
		Email: email,
	})
	return PayloadTask(payload, taskType, err)
}

func PayloadTask(payload []byte, taskType string, err error) (*asynq.Task, error) {
	if err != nil {
		return nil, err
	}
	return asynq.NewTask(taskType, payload, asynq.MaxRetry(maxRetry), asynq.Timeout(asyncTimeout)), nil
}
