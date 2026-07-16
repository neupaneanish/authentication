//go:build integration

package redis_test

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valkey-io/valkey-go"

	"neupaneanish.com.np/authentication/internal/config"
	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/tests"
)

var (
	vk valkey.Client
)

func TestMain(m *testing.M) {
	ctx := context.Background()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	url, cleanup, valkeyErr := tests.Valkey()

	if valkeyErr != nil {
		logger.Error("Failed to start valkey", "error", valkeyErr)
		os.Exit(1)
	}

	client, clientErr := config.NewValkey(ctx, url)
	if clientErr != nil {
		logger.Error("Failed to configure valkey", "error", clientErr)
		os.Exit(1)
	}

	vk = client

	m.Run()
	cleanup()
}

func TestRedis(t *testing.T) {
	t.Parallel()

	prefix := "test:prefix"
	prefix1 := "test:prefix:1"

	type data struct {
		Key  string    `json:"key"  valkey:",key"`
		Ver  int64     `json:"ver"  valkey:",ver"`
		ExAt time.Time `json:"exat" valkey:",exat"`
		Name string    `json:"name"`
	}

	value := &data{
		Key:  "test",
		ExAt: time.Now().Add(5 * time.Second),
		Name: "Test",
	}

	value1 := &data{
		Key:  "test2",
		ExAt: time.Now().Add(5 * time.Second),
		Name: "Test2",
	}

	t.Run("HSet", func(t *testing.T) {
		t.Parallel()
		hSetErr := redis.HSet[data](t.Context(), prefix, value, vk)
		require.NoError(t, hSetErr)
	})

	t.Run("HGet", func(t *testing.T) {
		t.Parallel()
		hSetErr := redis.HSet[data](t.Context(), prefix1, value1, vk)
		require.NoError(t, hSetErr)

		hGetData, hGetErr := redis.HGet[data](t.Context(), prefix1, value1.Key, vk)
		require.NoError(t, hGetErr)
		assert.NotNil(t, hGetData)
		assert.Equal(t, value1.Name, hGetData.Name)
	})

	t.Run("Delete", func(t *testing.T) {
		t.Parallel()
		hDeleteErr := redis.HDelete[data](t.Context(), prefix, value.Key, vk)
		require.NoError(t, hDeleteErr)
	})

	t.Run("Delete Delete", func(t *testing.T) {
		t.Parallel()
		hDeleteErr := redis.HDelete[data](t.Context(), prefix, value.Key, vk)
		require.NoError(t, hDeleteErr)
	})

	t.Run("Om failed", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(t.Context(), time.Microsecond)
		defer cancel()

		hGetData, hGetErr := redis.HGet[data](ctx, prefix, value.Key, vk)
		require.Error(t, hGetErr)
		assert.Nil(t, hGetData)
	})
}
