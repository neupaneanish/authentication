package config

import (
	"context"

	"github.com/twmb/franz-go/pkg/kgo"
)

func NewRedpanda(ctx context.Context, url, group string) (*kgo.Client, error) {
	client, err := kgo.NewClient(
		kgo.SeedBrokers(url),
		kgo.ConsumerGroup(group),
		kgo.WithContext(ctx),
	)
	if err != nil {
		return nil, err
	}

	if pingErr := client.Ping(ctx); pingErr != nil {
		client.Close()
		return nil, pingErr
	}

	return client, nil
}
