package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/hibiken/asynq"
	"github.com/smtp2go-oss/smtp2go-go"
	"neupaneanish.com.np/authentication/internal/task"
)

const (
	concurrency = 10
	critical    = 6
	base        = 3
	low         = 1
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	logger.Info("Loading Worker Environment")
	env, envErr := task.LoadWorkerEnv()
	if envErr != nil {
		logger.Error("Worker Env loading failed", "error", envErr)
		return
	}

	if err := os.Setenv(smtp2go.APIKeyEnv, env.SMTP2GO); err != nil {
		logger.Error("Failed to set SMTP2GO API Key", "error", env)
		return
	}

	logger.Info("Server loading")
	srv := asynq.NewServer(
		asynq.RedisClientOpt{Addr: env.ValkeyURL, DB: 0},
		asynq.Config{
			Concurrency: concurrency,
			Queues: map[string]int{
				"critical": critical,
				"default":  base,
				"low":      low,
			},
			ErrorHandler: asynq.ErrorHandlerFunc(func(ctx context.Context, task *asynq.Task, err error) {
				logger.ErrorContext(ctx, "asynq task execution failed", "task", task.Type(), "error", err)
			}),
		},
	)

	if pingErr := srv.Ping(); pingErr != nil {
		logger.Error("could connect to server", "error", pingErr)
		return
	}

	emailTask := task.NewEmailHandler(env)

	mux := asynq.NewServeMux()
	mux.HandleFunc(task.TypeForgetPassword, emailTask.HandleAuthEmailTask)
	mux.HandleFunc(task.TypeEmailVerification, emailTask.HandleAuthEmailTask)
	mux.HandleFunc(task.TypeAccountVerification, emailTask.HandleAuthEmailTask)
	mux.HandleFunc(task.TypePasswordReset, emailTask.HandleSecurityEmailTask)
	mux.HandleFunc(task.TypePasswordChanged, emailTask.HandleSecurityEmailTask)
	mux.HandleFunc(task.TypeTwoFactor, emailTask.HandleSecurityEmailTask)

	logger.Info("Go Asynq Worker running and listening for jobs...")
	if err := srv.Run(mux); err != nil {
		logger.Error("could not run server", "error", err)
		return
	}
}
