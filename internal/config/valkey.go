package config

import (
	"context"

	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeyotel"
)

func NewValkey(ctx context.Context, url string) (valkey.Client, error) {
	client, err := valkeyotel.NewClient(valkey.ClientOption{
		InitAddress:  []string{url},
		DisableCache: false,
	})
	if err != nil {
		return nil, err
	}

	if pingErr := client.Do(ctx, client.B().Ping().Build()).Error(); pingErr != nil {
		client.Close()
		return nil, pingErr
	}

	return client, nil
}
