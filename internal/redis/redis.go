package redis

import (
	"context"
	"time"

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

func SAdd(ctx context.Context, key, session string, ttl time.Duration, client valkey.Client) error {
	sAddCmd := client.B().Sadd().Key(key).Member(session).Build()
	if err := client.Do(ctx, sAddCmd).Error(); err != nil {
		return err
	}

	expireCmd := client.B().Expire().Key(key).Seconds(int64(ttl.Seconds())).Build()
	return client.Do(ctx, expireCmd).Error()
}

func SMembers(ctx context.Context, key string, client valkey.Client) ([]string, error) {
	cmd := client.B().Smembers().Key(key).Build()

	return client.Do(ctx, cmd).AsStrSlice()
}

func SRem(ctx context.Context, key string, session string, client valkey.Client) error {
	cmd := client.B().Srem().Key(key).Member(session).Build()
	return client.Do(ctx, cmd).Error()
}

func Del(ctx context.Context, key string, client valkey.Client) error {
	cmd := client.B().Del().Key(key).Build()
	return client.Do(ctx, cmd).Error()
}
