package config

import (
	"context"
	"errors"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"

	"neupaneanish.com.np/authentication/internal/utils"
)

func NewRedpanda(ctx context.Context, url, group string) (*kgo.Client, error) {
	client, err := kgo.NewClient(
		kgo.SeedBrokers(url),
		kgo.ConsumerGroup(group),
		kgo.AllowAutoTopicCreation(),
	)
	if err != nil {
		return nil, err
	}

	if pingErr := client.Ping(ctx); pingErr != nil {
		client.Close()
		return nil, pingErr
	}

	cl := kadm.NewClient(client)
	responses, topicErr := cl.CreateTopics(ctx, 1, 1, nil,
		utils.RedpandaAuthEmailNotificationTopic,
		utils.RedpandaSecurityEmailNotificationTopic,
		utils.RedpandaRootNotificationTopic,
	)

	if topicErr != nil {
		client.Close()
		return nil, topicErr
	}

	for _, resp := range responses {
		if resp.Err != nil {
			if !errors.Is(resp.Err, kerr.TopicAlreadyExists) {
				client.Close()
				return nil, resp.Err
			}
		}
	}

	return client, nil
}
