package task

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/hibiken/asynq"
	"github.com/smtp2go-oss/smtp2go-go"
)

type EmailHandler struct {
	senderEmail string
}

func NewEmailHandler(env *Env) *EmailHandler {
	return &EmailHandler{
		senderEmail: env.SenderEmail,
	}
}

func (h *EmailHandler) HandleAuthEmailTask(_ context.Context, t *asynq.Task) error {
	var payload EmailTaskPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return errors.New("failed to deserialize payload")
	}
	if payload.Email == "" || payload.Code == "" {
		return errors.New("payload cannot be empty")
	}

	templateData := map[string]any{"code": payload.Code}

	return SendEmail(h.senderEmail, payload.Email, t.Type(), templateData)
}

func (h *EmailHandler) HandleSecurityEmailTask(_ context.Context, t *asynq.Task) error {
	var payload SecurityEmailTaskPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return errors.New("failed to deserialize payload")
	}

	if payload.Email == "" {
		return errors.New("email cannot be empty")
	}

	templateData := map[string]any{}

	return SendEmail(h.senderEmail, payload.Email, t.Type(), templateData)
}

func SendEmail(fromEmail string, toEmail string, templateID string, templateData any) error {
	email := &smtp2go.Email{
		From:         fromEmail,
		To:           []string{toEmail},
		TemplateID:   templateID,
		TemplateData: templateData,
	}

	_, resErr := smtp2go.Send(email)
	if resErr != nil {
		return resErr
	}

	return nil
}
