package redis

import (
	"context"

	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/om"
)

func HSet[T any](
	ctx context.Context,
	prefix string,
	data *T,
	client valkey.Client,
) error {
	var zero T
	repo := om.NewHashRepository[T](prefix, zero, client)
	return repo.Save(ctx, data)
}

func HGet[T any](
	ctx context.Context,
	prefix string,
	key string,
	client valkey.Client,
) (*T, error) {
	var zero T
	repo := om.NewHashRepository[T](prefix, zero, client)
	value, err := repo.Fetch(ctx, key)
	if err != nil {
		return nil, err
	}
	return value, nil
}

func HDelete[T any](
	ctx context.Context,
	prefix string,
	key string,
	client valkey.Client,
) error {
	var zero T
	repo := om.NewHashRepository[T](prefix, zero, client)
	return repo.Remove(ctx, key)
}
