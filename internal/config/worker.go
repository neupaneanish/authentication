package config

import (
	"github.com/hibiken/asynq"
)

func NewWorker(url string) (*asynq.Client, error) {
	client := asynq.NewClient(asynq.RedisClientOpt{Addr: url, DB: 0})

	if pingErr := client.Ping(); pingErr != nil {
		_ = client.Close()
		return nil, pingErr
	}

	return client, nil
}
