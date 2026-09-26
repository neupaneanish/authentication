package redpanda

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"
	"uuid"

	"github.com/twmb/franz-go/pkg/kgo"

	"neupaneanish.com.np/authentication/internal/utils"
)

func produce[T any](
	ctx context.Context,
	key uuid.UUID,
	topic, serviceName string,
	payload T,
	client *kgo.Client,
	logger *slog.Logger,
) {
	value, err := json.Marshal(payload)
	if err != nil {
		logger.ErrorContext(ctx, "failed to produce message", "service", serviceName, "key", key, "error", err)
		return
	}
	record := &kgo.Record{
		Key:       []byte(key.String()),
		Value:     value,
		Timestamp: time.Now().UTC(),
		Topic:     topic,
	}

	ctx = context.WithoutCancel(ctx)

	client.Produce(ctx, record, func(_ *kgo.Record, err error) {
		if err != nil {
			logger.ErrorContext(
				ctx, "failed to deliver message to redpanda",
				"service", serviceName,
				"topic", topic,
				"key", key.String(),
				"error", err,
			)
		}
	})
}

func AuthEmailProduce(
	ctx context.Context,
	key uuid.UUID,
	value, email, emailTemplate, serviceName string,
	client *kgo.Client,
	logger *slog.Logger,
) {
	payload := utils.AuthEmail{
		Value:         value,
		Email:         email,
		EmailTemplate: emailTemplate,
	}
	produce[utils.AuthEmail](ctx, key, utils.RedpandaAuthEmailNotificationTopic, serviceName, payload, client, logger)
}

func SecurityEmailProduce(
	ctx context.Context,
	key uuid.UUID,
	email, emailTemplate, serviceName string,
	client *kgo.Client,
	logger *slog.Logger,
) {
	payload := utils.SecurityEmail{
		Email:         email,
		EmailTemplate: emailTemplate,
	}
	produce[utils.SecurityEmail](
		ctx,
		key,
		utils.RedpandaSecurityEmailNotificationTopic,
		serviceName,
		payload,
		client,
		logger,
	)
}

func RootNotificationProduce(
	ctx context.Context,
	actorID, userID uuid.UUID,
	username, table, method, serviceName string,
	client *kgo.Client,
	logger *slog.Logger,
) {
	payload := utils.RootNotification{
		ActorID:  actorID,
		UserID:   userID,
		Username: username,
		Table:    table,
		Method:   method,
	}

	produce[utils.RootNotification](
		ctx,
		userID,
		utils.RedpandaRootNotificationTopic,
		serviceName,
		payload,
		client,
		logger,
	)
}
