//go:build integration

package redis_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"neupaneanish.com.np/authentication/internal/config"
	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/tests"
)

func TestRedis(t *testing.T) {
	url, cleanup, valkeyErr := tests.Valkey()
	require.NoError(t, valkeyErr)
	assert.NotNil(t, url)
	t.Cleanup(cleanup)

	client, clientErr := config.NewValkey(t.Context(), url)
	require.NoError(t, clientErr)
	assert.NotNil(t, client)
	prefix := "test:prefix"

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

	t.Run("HSet", func(t *testing.T) {
		hSetErr := redis.HSet[data](t.Context(), prefix, value, client)
		require.NoError(t, hSetErr)
	})

	t.Run("HGet", func(t *testing.T) {
		hGetData, hGetErr := redis.HGet[data](t.Context(), prefix, value.Key, client)
		require.NoError(t, hGetErr)
		assert.NotNil(t, hGetData)
		assert.Equal(t, value.Name, hGetData.Name)
	})

	t.Run("Delete", func(t *testing.T) {
		hDeleteErr := redis.HDelete[data](t.Context(), prefix, value.Key, client)
		require.NoError(t, hDeleteErr)
	})

	t.Run("Delete Delete", func(t *testing.T) {
		hDeleteErr := redis.HDelete[data](t.Context(), prefix, value.Key, client)
		require.NoError(t, hDeleteErr)
	})

	t.Run("Om failed", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Microsecond)
		defer cancel()

		hGetData, hGetErr := redis.HGet[data](ctx, prefix, value.Key, client)
		require.Error(t, hGetErr)
		assert.Nil(t, hGetData)
	})
}
