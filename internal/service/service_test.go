//go:build integration || benchmark || e2e

package service_test

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"neupaneanish.com.np/api/internal/config"
	"neupaneanish.com.np/api/internal/enum"
	authv1 "neupaneanish.com.np/api/internal/protobuf/auth/v1"
	"neupaneanish.com.np/api/internal/repository"
	"neupaneanish.com.np/api/internal/service"
	"neupaneanish.com.np/api/internal/telemetry"
	"neupaneanish.com.np/api/internal/transport"
	"neupaneanish.com.np/api/internal/utils"
	"neupaneanish.com.np/api/tests"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"

	// Register the file source driver for migrations.
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

var (
	cfg               *config.Config
	authServiceClient authv1.AuthServiceClient
)

type container struct {
	dbURL            string
	dbCleanup        func()
	vkURL            string
	vkCleanup        func()
	telemetryURL     string
	telemetryCleanup func()
}

func TestMain(m *testing.M) {
	ctx := context.Background()
	testContainer := setupContainer()

	testEnv := setupEnv(testContainer.dbURL, testContainer.vkURL)

	logger, loggerCleanup, loggerErr := telemetry.NewTelemetry(
		ctx,
		testContainer.telemetryURL,
		testEnv.ServiceName,
		testEnv.Environment,
	)

	if loggerErr != nil {
		slog.Error("Failed to start telemetry", "error", loggerErr)
		os.Exit(1)
	}

	testCfg, testCfgErr := config.NewConfig(ctx, testEnv, logger)
	if testCfgErr != nil {
		slog.Error("Failed to setup config", "error", testCfgErr)
		os.Exit(1)
	}

	cfg = testCfg

	client, server, testClientServerErr := testClientServer(testCfg)
	if testClientServerErr != nil {
		slog.Error("Failed to start client / server", "error", testCfgErr)
		os.Exit(1)
	}

	authServiceClient = authv1.NewAuthServiceClient(client)

	code := m.Run()
	loggerCleanupErr := loggerCleanup(ctx)
	if loggerCleanupErr != nil {
		slog.Error("Failed to cleanup logger", "error", loggerCleanupErr)
		os.Exit(1)
	}

	err := client.Close()
	if err != nil {
		slog.Error("Failed to close client", "error", err)
		os.Exit(1)
	}
	server.GracefulStop()
	testContainer.dbCleanup()
	testContainer.vkCleanup()
	testContainer.telemetryCleanup()

	os.Exit(code)
}

func setupContainer() *container {
	dbURL, dbCleanup, dbErr := tests.Postgres()
	if dbErr != nil {
		slog.Error("Failed to start postgres container", "error", dbErr)
		os.Exit(1)
	}

	migrationErr := runMigrations(dbURL)
	if migrationErr != nil {
		slog.Error("Failed to migrations", "error", migrationErr)
		os.Exit(1)
	}

	vkURL, vkCleanup, vkErr := tests.Valkey()
	if vkErr != nil {
		slog.Error("Failed to start valkey container", "error", vkErr)
		os.Exit(1)
	}

	telemetryURL, telemetryCleanup, telemetryErr := tests.OpenTelemetry()
	if telemetryErr != nil {
		slog.Error("Failed to start telemetry container", "error", telemetryErr)
		os.Exit(1)
	}

	return &container{
		dbURL:            dbURL,
		dbCleanup:        dbCleanup,
		vkURL:            vkURL,
		vkCleanup:        vkCleanup,
		telemetryURL:     telemetryURL,
		telemetryCleanup: telemetryCleanup,
	}
}

func setupEnv(db string, vk string) *config.Env {
	_, jwtPrivate, jwtKeyErr := ed25519.GenerateKey(nil)
	if jwtKeyErr != nil {
		slog.Error("Failed to validate jwtKey", "error", jwtKeyErr)
		os.Exit(1)
	}

	_, tfPrivate, tfKeyErr := ed25519.GenerateKey(nil)
	if tfKeyErr != nil {
		slog.Error("Failed to validate tfKey", "error", tfKeyErr)
		os.Exit(1)
	}

	return &config.Env{
		DatabaseURL:  db,
		ValkeyURL:    vk,
		JWTKey:       hex.EncodeToString(jwtPrivate.Seed()),
		TwoFactorKey: hex.EncodeToString(tfPrivate.Seed()),
		Issuer:       "Test",
		Environment:  "test",
		ServiceName:  "Test",
		Domain:       "api.neupaneanish.com.np",
	}
}

func testClientServer(cfg *config.Config) (*grpc.ClientConn, *grpc.Server, error) {
	listen := bufconn.Listen(1024 * 1024)

	opts, optsErr := transport.NewOptions(cfg)

	if optsErr != nil {
		return nil, nil, optsErr
	}

	server := grpc.NewServer(opts...)

	authv1.RegisterAuthServiceServer(server, service.NewAuthService(cfg))

	go func() {
		if err := server.Serve(listen); err != nil {
			slog.Error("Failed to serve server", "error", err)
			os.Exit(1)
		}
	}()

	client, clientErr := grpc.NewClient(
		"passthrough://bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listen.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)

	if clientErr != nil {
		return nil, nil, clientErr
	}

	return client, server, nil
}

func runMigrations(url string) error {
	_, b, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(b), "..", "..")
	migrationsPath := filepath.Join(root, "database", "migrations")

	db, dbErr := sql.Open("postgres", url)
	if dbErr != nil {
		return dbErr
	}

	defer func() {
		_ = db.Close()
	}()

	driver, driverErr := postgres.WithInstance(db, &postgres.Config{})
	if driverErr != nil {
		return driverErr
	}

	m, mErr := migrate.NewWithDatabaseInstance(
		"file://"+migrationsPath,
		"postgres",
		driver,
	)
	if mErr != nil {
		return mErr
	}

	defer func() {
		_, _ = m.Close()
	}()

	upErr := m.Up()
	if upErr != nil && !errors.Is(upErr, migrate.ErrNoChange) {
		return upErr
	}

	return nil
}

func seedUser(ctx context.Context, email string, password string, status enum.UserStatus) (string, error) {
	tx, txErr := cfg.Pool.Begin(ctx)
	if txErr != nil {
		return "", txErr
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	qtx := repository.New(tx)

	userParams := &repository.CreateUserParams{
		Email:     email,
		Username:  email,
		Role:      enum.UserRoleUser,
		Status:    status,
		CreatedBy: uuid.Nil,
		UpdatedBy: uuid.Nil,
	}
	userRow, userRowErr := qtx.CreateUser(ctx, userParams)
	if userRowErr != nil {
		return "", userRowErr
	}

	hash, hashErr := utils.CreatePassword(password)
	if hashErr != nil {
		return "", hashErr
	}

	credentialsParams := &repository.CreateCredentialParams{
		UserID:    userRow.ID,
		Password:  hash,
		CreatedBy: userRow.ID,
	}

	affected, credentialsErr := qtx.CreateCredential(ctx, credentialsParams)
	if credentialsErr != nil {
		return "", credentialsErr
	}

	if affected.RowsAffected() == 0 {
		return "", errors.New("cannot create credentials")
	}

	if txCommitErr := tx.Commit(ctx); txCommitErr != nil {
		return "", txCommitErr
	}

	return userRow.ID.String(), nil
}
